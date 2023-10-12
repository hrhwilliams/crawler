#include <curl/curl.h>
#include <libxml/HTMLparser.h>
#include <sqlite3.h>

#include <getopt.h>

#include "md5.h"

#include <deque>
#include <iostream>
#include <memory>
#include <optional>
#include <cstring>
#include <vector>

/* useful SQL
 * select pages linked to by another page 'SELECT * FROM pages WHERE id IN (SELECT to_id FROM links WHERE from_id=<linking page>);'
 * select all pages that actually link to something in the db 'SELECT * FROM pages WHERE id IN (SELECT from_id FROM links);'
 * select all leaves 'SELECT url FROM pages WHERE id NOT in (SELECT from_id FROM links);'
 */

const int max_conn = 1;

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    reinterpret_cast<std::string*>(userp)->append((char*) contents, size * nmemb);
    return size * nmemb;
}

struct SQLError {
protected:
    char message_buf[1024];
public:
    SQLError(sqlite3 *db) {
        const int error_code = sqlite3_errcode(db);
        const char *error_string = sqlite3_errstr(error_code);
        snprintf(message_buf, sizeof(message_buf), "SQLError [%d]: %s", error_code, error_string);
    }

    SQLError(sqlite3 *db, sqlite3_stmt *stmt) {
        const int error_code = sqlite3_errcode(db);
        const char *error_string = sqlite3_errstr(error_code);
        const char *statement = sqlite3_sql(stmt);
        snprintf(message_buf, sizeof(message_buf), "SQLError [%d]: '%s': %s", error_code, statement, error_string);
        sqlite3_finalize(stmt);
    }

    SQLError(const char *error_type, sqlite3 *db) {
        const int error_code = sqlite3_errcode(db);
        const char *error_string = sqlite3_errstr(error_code);
        snprintf(message_buf, sizeof(message_buf), "%s [%d]: %s", error_type, error_code, error_string);
    }

    SQLError(const char *error_type, sqlite3 *db, sqlite3_stmt *stmt) {
        const int error_code = sqlite3_errcode(db);
        const char *error_string = sqlite3_errstr(error_code);
        const char *statement = sqlite3_sql(stmt);
        snprintf(message_buf, sizeof(message_buf), "%s [%d]: '%s': %s", error_type, error_code, statement, error_string);
        sqlite3_finalize(stmt);
    }

    char *what() {
        return message_buf;
    }
};

struct SQLPrepareError : public SQLError {
    // stmt is null because it's not compiled here, so need to accept raw input and maybe the syntax error msg
    SQLPrepareError(sqlite3 *db) : SQLError("SQLPrepareError", db) {}
    SQLPrepareError(sqlite3 *db, sqlite3_stmt *stmt) : SQLError("SQLPrepareError", db, stmt) {}
    SQLPrepareError(sqlite3 *db, char *stmt) : SQLError(db) {
        const int error_code = sqlite3_errcode(db);
        const char *error_string = sqlite3_errstr(error_code);
        snprintf(message_buf, sizeof(message_buf), "SQLPrepareError [%d] on input '%s': %s", error_code, stmt, error_string);
    }
};

struct SQLConstraintError : public SQLError {
    SQLConstraintError(sqlite3 *db) : SQLError("SQLConstraintError", db) {}
    SQLConstraintError(sqlite3 *db, sqlite3_stmt *stmt) : SQLError("SQLConstraintError", db, stmt) {}
};

struct SQLRowNotFoundError : public SQLError {
    SQLRowNotFoundError(sqlite3 *db) : SQLError("SQLRowNotFoundError", db) {}
    SQLRowNotFoundError(sqlite3 *db, sqlite3_stmt *stmt) : SQLError("SQLRowNotFoundError", db, stmt) {}
};

class DatabaseAccessObject {
private:
    sqlite3 *db = nullptr;
    char stmt_buffer[4096];

    void execute_sql_statement(const char *statement, ...) {
        va_list argp;
        va_start(argp, statement);
        int rc = 0;
        sqlite3_stmt *compiled_stmt = nullptr;
        int bytes_written = vsnprintf(stmt_buffer, sizeof(stmt_buffer), statement, argp);

        rc = sqlite3_prepare_v2(db, stmt_buffer, bytes_written, &compiled_stmt, nullptr);
        if (rc != SQLITE_OK) {
            throw SQLPrepareError(db, stmt_buffer);
        }

        if ((rc = sqlite3_step(compiled_stmt)) != SQLITE_DONE) {
            if (rc == SQLITE_CONSTRAINT) {
                // throw SQLConstraintError(db, compiled_stmt);
            }

            throw SQLError(db, compiled_stmt);
        }

        sqlite3_finalize(compiled_stmt);
        va_end(argp);
    }

    std::optional<int> execute_sql_select_int_statement(const char *statement, ...) {
        va_list argp;
        va_start(argp, statement);
        int rc = 0;
        sqlite3_stmt *compiled_stmt = nullptr;
        int bytes_written = vsnprintf(stmt_buffer, sizeof(stmt_buffer), statement, argp);

        rc = sqlite3_prepare_v2(db, stmt_buffer, bytes_written, &compiled_stmt, nullptr);
        if (rc != SQLITE_OK) {
            throw SQLPrepareError(db, compiled_stmt);
        }

        if (sqlite3_step(compiled_stmt) != SQLITE_ROW) {
            sqlite3_finalize(compiled_stmt);

            if (rc == SQLITE_DONE) {
                return std::nullopt;
                throw SQLRowNotFoundError(db, compiled_stmt);
            }

            throw SQLError(db, compiled_stmt);
        }

        int integer = sqlite3_column_int(compiled_stmt, 0);

        sqlite3_finalize(compiled_stmt);
        va_end(argp);
        return std::optional<int> { integer };
    }

    std::string execute_sql_select_str_statement(const char *statement, ...) {
        va_list argp;
        va_start(argp, statement);
        int rc = 0;
        sqlite3_stmt *compiled_stmt = nullptr;
        int bytes_written = vsnprintf(stmt_buffer, sizeof(stmt_buffer), statement, argp);

        rc = sqlite3_prepare_v2(db, stmt_buffer, bytes_written, &compiled_stmt, nullptr);
        if (rc != SQLITE_OK) {
            throw SQLPrepareError(db, compiled_stmt);
        }

        if (sqlite3_step(compiled_stmt) != SQLITE_ROW) {
            sqlite3_finalize(compiled_stmt);

            if (rc == SQLITE_DONE) {
                throw SQLRowNotFoundError(db, compiled_stmt);
            }

            throw SQLError(db, compiled_stmt);
        }

        const unsigned char *text = sqlite3_column_text(compiled_stmt, 0);
        int bytes = sqlite3_column_bytes(compiled_stmt, 0);
        std::string text_string = std::string(reinterpret_cast<const char*>(text));

        sqlite3_finalize(compiled_stmt);
        va_end(argp);
        return text_string;
    }

    void create_tables() {
        static const char pages_schema[] = 
            "CREATE TABLE IF NOT EXISTS pages (\n"
            "    id INTEGER PRIMARY KEY,\n"
            "    url TEXT UNIQUE NOT NULL,\n"
            "    visited TEXT,\n"
            "    md5 TEXT\n"
            ");";

        static const char links_schema[] =
            "CREATE TABLE IF NOT EXISTS links (\n"
            "    id INTEGER PRIMARY KEY,\n"
            "    from_id INTEGER NOT NULL,\n"
            "    to_id INTEGER NOT NULL,\n"
            "    UNIQUE(from_id, to_id),\n"
            "    FOREIGN KEY (from_id)\n"
            "        REFERENCES pages (id),\n"
            "    FOREIGN KEY (to_id)\n"
            "        REFERENCES pages (id)\n"
            ");";

        execute_sql_statement(pages_schema);
        execute_sql_statement(links_schema);
    }

    bool valid_sql(const char *stmt) const {
        for (int i = 0; stmt[i] != '\0'; i++) {
            if (stmt[i] == ';' || stmt[i] == '\"') {
                return false;
            }
        }

        return true;
    }
public:
    DatabaseAccessObject(const char *database_name) {
        int rc = sqlite3_open_v2(database_name, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);

        if (rc) {
            throw SQLError(db);
        }

        create_tables();
    }

    bool page_in_database(const std::string &url) {
        int id1 = execute_sql_select_int_statement("SELECT id FROM pages WHERE url=\"%s\";", url1.c_str());
    }

    bool insert_page(const std::string &url) {
        if (!valid_sql(url.c_str())) {
            return false;
        }

        execute_sql_statement("INSERT INTO pages(url) VALUES(\"%s\");", url.c_str());

        return true;
    }

    bool update_md5(const std::string &url, std::string page) {
        if (!valid_sql(url.c_str())) {
            return false;
        }

        MD5_CTX context;
        unsigned char digest[16];
        unsigned char digest_string[33];
        unsigned int len = page.length();

        MD5Init(&context);
        MD5Update(&context, reinterpret_cast<unsigned char*>(&page[0]), len);
        MD5Final(digest, &context);

        for (unsigned int i = 0; i < 16; i++) {
            digest_string[i*2+1] = digest[i] & 0x0f;
            digest_string[i*2]   = (digest[i] & 0xf0) >> 4;

            digest_string[i*2+1] = digest_string[i*2+1] < 10 ? digest_string[i*2+1] + '0' : (digest_string[i*2+1] - 10) + 'a';
            digest_string[i*2] = digest_string[i*2] < 10 ? digest_string[i*2] + '0' : (digest_string[i*2] - 10) + 'a';
        }
        digest_string[32] = '\0';

        execute_sql_statement("UPDATE pages SET md5=\"%s\" WHERE url=\"%s\";", digest_string, url.c_str());
        execute_sql_statement("UPDATE pages SET visited=date() WHERE url=\"%s\";", digest_string, url.c_str());
        return true;
    }

    bool link_pages(const std::string &url1, const std::string &url2) {
        if (!valid_sql(url1.c_str()) || !valid_sql(url2.c_str())) {
            return false;
        }

        int id1 = execute_sql_select_int_statement("SELECT id FROM pages WHERE url=\"%s\";", url1.c_str());
        int id2 = execute_sql_select_int_statement("SELECT id FROM pages WHERE url=\"%s\";", url2.c_str());
        execute_sql_statement("INSERT INTO links (from_id, to_id) VALUES(%d, %d);", id1, id2);
        return true;
    }
};

class CURLHandle {
private:
    CURL *handle = nullptr;
    CURLU *url_handle = nullptr;
    std::string _url = {};
    std::string _buffer = {};
public:
    CURLHandle(const std::string &url) : _url(url) {
        
    }

    CURLHandle(CURLHandle &&rhs) noexcept {
        std::swap(this->handle, rhs.handle);
        std::swap(this->url_handle, rhs.url_handle);

        this->_buffer = rhs._buffer;
        this->_url = rhs._url;
        curl_easy_setopt(this->handle, CURLOPT_WRITEDATA, &_buffer);
    }

    CURLHandle& operator=(CURLHandle &&rhs) noexcept {
        std::swap(this->handle, rhs.handle);
        std::swap(this->url_handle, rhs.url_handle);

        this->_buffer = rhs._buffer;
        this->_url = rhs._url;
        curl_easy_setopt(this->handle, CURLOPT_WRITEDATA, &_buffer);
        return *this;
    }

    CURLHandle(const CURLHandle &rhs) = delete;
    CURLHandle& operator=(const CURLHandle &rhs) = delete;

    ~CURLHandle() {
        
        if (handle != nullptr) { curl_easy_cleanup(handle); }
        if (url_handle != nullptr) { curl_url_cleanup(url_handle); }
    }

    CURL* get_handle() const {
        return handle;
    }

    CURLcode perform() {
        // curl_easy_setopt(handle, CURLOPT_WRITEDATA, &_buffer);
        handle = curl_easy_init();
        url_handle = curl_url();
        if (curl_url_set(url_handle, CURLUPART_URL, _url.c_str(), 0) != CURLUE_OK) {
            throw std::runtime_error("URL Malformed");
        }

        curl_easy_setopt(handle, CURLOPT_VERBOSE, 0);
        curl_easy_setopt(handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
        curl_easy_setopt(handle, CURLOPT_HTTPGET, 1);
        if (curl_easy_setopt(handle, CURLOPT_URL, _url.c_str()) != CURLE_OK) {
            throw std::runtime_error("URL Malformed");
        }

        curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, &write_callback);
        curl_easy_setopt(handle, CURLOPT_WRITEDATA, &_buffer);

        curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1);
        curl_easy_setopt(handle, CURLOPT_TIMEOUT, 10);
        curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, 5);

        return curl_easy_perform(handle);
    }

    std::string get_url() const {
        return _url;
    }

    std::string parse_relative_url(const std::string &url) const {
        char *url_cstring;
        CURLU *new_handle = curl_url_dup(url_handle);
        auto rc = curl_url_set(new_handle, CURLUPART_URL, url.c_str(), 0);
        rc = curl_url_get(new_handle, CURLUPART_URL, &url_cstring, 0);

        std::string url_string(url_cstring);

        curl_free(url_cstring);
        curl_url_cleanup(new_handle);
        return url_string;
    }

    std::string get_buffer() const {
        return _buffer;
    }

    long get_response_code() const {
        long response_code;
        curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &response_code);
        return response_code;
    }
};

std::vector<std::string> get_hrefs(const std::string &page) {
    std::vector<std::string> hrefs;

    for (int i = 0; i < page.length() - 2; i++) {
        // beginning of an '<a ...' tag
        if (page[i] == '<' && (page[i+1] == 'a' || page[i+1] == 'A') && page[i+2] == ' ') {
            for (int j = i + 2; j < page.length() - 6; j++) {
                if (page[j] == '>') {
                    i = j;
                    break;
                }

                if ((page[j] == 'h' || page[j] == 'H') && (page[j+1] == 'r' || page[j+1] == 'R') && (page[j+2] == 'e' || page[j+2] == 'E') && (page[j+3] == 'f' || page[j+3] == 'F') && page[j+4] == '=' && page[j+5] == '"') {
                    if (page[j+6] == '#') {
                        continue;
                    }
                    for (int k = j + 6; k < page.length(); k++) {
                        if (page[k] == '"') {
                            hrefs.push_back(std::string(page.c_str() + j + 6, k - (j + 6)));
                            break;
                        }
                    }
                }
            }
        }
    }

    return hrefs;
}

int main(int argc, char *argv[]) {
    try {
        auto dao = DatabaseAccessObject(argv[1]);

        // std::cout << "SQLite3 version " << sqlite3_libversion() << '\n';

        // SQLITE_OPEN_NOMUTEX
        // The new database connection will use the "multi-thread" threading mode. 
        // This means that separate threads are allowed to use SQLite at the same time, 
        // as long as each thread is using a different database connection.

        // SQLITE_OPEN_FULLMUTEX
        // The new database connection will use the "serialized" threading mode. This 
        // means the multiple threads can safely attempt to use the same database connection
        //  at the same time. (Mutexes will block any actual concurrency, but in this
        // mode there is no harm in trying.)

        curl_global_init(CURL_GLOBAL_DEFAULT);

        std::string starting_url = "https://en.wikipedia.org/wiki/SHA-2";
                                // "https://csrc.nist.gov/groups/STM/cavp/documents/shs/shaval.htm"
        std::deque<CURLHandle> link_queue;
        link_queue.emplace_back(starting_url);
        
        // https://fse2012.inria.fr/SLIDES/67.pdf throws CURLE_PEER_FAILED_VERIFICATION (60)

        // need redirect timeout
        // http://csrc.nist.gov/groups/STM/cavp/documents/shs/shaval.htm crashes

        dao.insert_page(starting_url);

        long response_code;

        for (int i = 0; !link_queue.empty(); i++) {
            CURLHandle handle = std::move(link_queue.front());
            link_queue.pop_front();

            const auto url = handle.get_url();
            std::cout << url << "\n";
            const auto code = handle.perform();
            if (code != CURLE_OK) {
                if (code == CURLE_OPERATION_TIMEDOUT || code == CURLE_PEER_FAILED_VERIFICATION) {
                    continue;
                }
                throw std::runtime_error(std::to_string((int) code));
            } else {
                auto response_code = handle.get_response_code();
                std::cout << response_code << "\n";

                if (response_code == 404) {
                    continue;
                }

                // if (response_code == 302) {
                //     struct curl_header *type;
                //     auto hrc = curl_easy_header(handle.get_handle(), "Location", 0, CURLH_HEADER, -1, &type);
                //     auto redirect = type->value;
                //     link_queue.emplace_front(redirect);
                //     continue;
                // }
            }

            try {
                dao.update_md5(url, handle.get_buffer());
            } catch (SQLError &e) {
                std::cerr << e.what() << " " << url << std::endl;
                // return 0;
            }

            const auto hrefs = get_hrefs(handle.get_buffer());

            for (const auto &href : hrefs) {
                if (href.length() == 0) {
                    continue;
                }

                const auto absolute_url = handle.parse_relative_url(href);
                std::cout << "    " << absolute_url << "\n";
                
                try {
                    // now it never inserts a new md5 because the entry will already exist when it finally scrapes the page
                    // so idk bleh i should restructure all of this shouldnt i
                    dao.insert_page(absolute_url);
                    dao.link_pages(url, absolute_url);
                } catch (SQLError &e) {
                    // std::cerr << e.what() << std::endl;
                    continue;
                }

                link_queue.emplace_back(absolute_url);
            }
        }
    } catch (SQLError &e) {
        std::cerr << e.what() << '\n';
        return -1;
    }

    return 0;
}
