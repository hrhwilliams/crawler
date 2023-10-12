#include <curl/curl.h>
#include <libxml/HTMLparser.h>
#include <sqlite3.h>

#include <getopt.h>

#include "md5.h"

#include <array>
#include <deque>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <cstring>
#include <vector>
#include <queue>

static int verbose_flag;

static struct option long_options[] = {
    { "verbose",   no_argument,       &verbose_flag,  1  },
    { "help",      no_argument,       0,             'h' },
    { "database",  required_argument, 0,             'd' },
    { "url",       required_argument, 0,             'u' },
    { 0,           0,                 0,              0  }
};

struct SQLDeleter {
    void operator()(sqlite3 *db) noexcept { sqlite3_close_v2(db); }
    void operator()(sqlite3_stmt *stmt) noexcept { sqlite3_finalize(stmt); }
};

struct CURLDeleter {
    void operator()(CURL *ptr) noexcept { curl_easy_cleanup(ptr); }
    void operator()(CURLU *ptr) noexcept { curl_url_cleanup(ptr); }
};

struct CURLMDeleter {
    void operator()(CURLM *ptr) {
        auto code = curl_multi_cleanup(ptr);
        if (code != CURLM_OK) {
            throw std::runtime_error(std::to_string(code));
        }
    }
};

using SQLiteHandle = std::unique_ptr<sqlite3, SQLDeleter>;
using SQLiteStatementHandle = std::unique_ptr<sqlite3_stmt, SQLDeleter>;
using CURLHandle = std::unique_ptr<CURL, CURLDeleter>;
using CURLUHandle = std::unique_ptr<CURLU, CURLDeleter>;
using CURLMHandle = std::unique_ptr<CURLM, CURLMDeleter>;


static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    reinterpret_cast<std::string*>(userp)->append((char*) contents, size * nmemb);
    return size * nmemb;
}

static std::string md5sum(std::string &string) {
    MD5_CTX context;
    unsigned char digest[16];
    char digest_string[33];

    MD5Init(&context);
    MD5Update(&context, reinterpret_cast<unsigned char*>(&string[0]), string.length());
    MD5Final(digest, &context);

    for (unsigned int i = 0; i < 16; i++) {
        digest_string[i*2+1] = digest[i] & 0x0f;
        digest_string[i*2]   = (digest[i] & 0xf0) >> 4;

        digest_string[i*2+1] = digest_string[i*2+1] < 10 ? digest_string[i*2+1] + '0' : (digest_string[i*2+1] - 10) + 'a';
        digest_string[i*2] = digest_string[i*2] < 10 ? digest_string[i*2] + '0' : (digest_string[i*2] - 10) + 'a';
    }
    digest_string[32] = '\0';

    return std::string(digest_string);
}


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


struct SQLError {
protected:
    char _buffer[1024];
    int _error_code = 0;
    const char *_error_string = nullptr;
    SQLError(const SQLiteHandle &db) {
        _error_code = sqlite3_errcode(db.get());
        _error_string = sqlite3_errstr(_error_code);
    }
public:
    char *what() {
        return _buffer;
    }
};

struct SQLBusyError : public SQLError {
    SQLBusyError(const SQLiteHandle &db, const SQLiteStatementHandle &stmt) : SQLError(db) {
        const char *statement = sqlite3_sql(stmt.get());
        snprintf(_buffer, sizeof(_buffer), "[ERROR] SQLBusyError (%d) on input '%s': %s", _error_code, statement, _error_string);
    }
};

struct SQLGenericError : public SQLError {
    SQLGenericError(const SQLiteHandle &db, const SQLiteStatementHandle &stmt) : SQLError(db) {
        const char *statement = sqlite3_sql(stmt.get());
        snprintf(_buffer, sizeof(_buffer), "[ERROR] SQLGenericError (%d) on input '%s': %s", _error_code, statement, _error_string);
    }
};

struct SQLPrepareError : public SQLError {
    SQLPrepareError(const SQLiteHandle &db, char *statement) : SQLError(db) {
        snprintf(_buffer, sizeof(_buffer), "[ERROR] SQLPrepareError (%d) on input '%s': %s", _error_code, statement, _error_string);
    }
};

struct SQLConstraintError : public SQLError {
    SQLConstraintError(const SQLiteHandle &db, const SQLiteStatementHandle &stmt) : SQLError(db) {
        const char *statement = sqlite3_sql(stmt.get());
        snprintf(_buffer, sizeof(_buffer), "[ERROR] SQLConstraintError (%d) on input '%s': %s", _error_code, statement, _error_string);
    }
};

struct SQLNotFoundError : public SQLError {
    SQLNotFoundError(const SQLiteHandle &db, const SQLiteStatementHandle &stmt) : SQLError(db) {
        const char *statement = sqlite3_sql(stmt.get());
        snprintf(_buffer, sizeof(_buffer), "[ERROR] SQLNotFoundError (%d) on input '%s': %s", _error_code, statement, _error_string);
    }
};

class SQLiteDatabaseAccessObject {
private:
    SQLiteHandle _db = nullptr;
    char _stmt_buffer[4096];

    SQLiteStatementHandle prepare_sql_statement(const char *statement, va_list argp) {
        int rc = 0;
        sqlite3_stmt *compiled_stmt = nullptr;
        int bytes_written = vsnprintf(_stmt_buffer, sizeof(_stmt_buffer), statement, argp);

        rc = sqlite3_prepare_v2(_db.get(), _stmt_buffer, bytes_written, &compiled_stmt, nullptr);
        if (rc != SQLITE_OK) {
            throw SQLPrepareError(_db, _stmt_buffer);
        }

        return SQLiteStatementHandle(compiled_stmt);
    }

    void execute_sql_statement(const char *statement, ...) {
        va_list argp;
        va_start(argp, statement);

        auto stmt = prepare_sql_statement(statement, argp);

        va_end(argp);

        int rc = sqlite3_step(stmt.get());
        if (rc != SQLITE_DONE) {
            if (rc == SQLITE_BUSY) {
                throw SQLBusyError(_db, stmt);
            } else if (rc == SQLITE_CONSTRAINT) {
                throw SQLConstraintError(_db, stmt);
            }

            throw SQLGenericError(_db, stmt);
        }
    }

    std::optional<int> execute_sql_select_int_statement(const char *statement, ...) {
        va_list argp;
        va_start(argp, statement);

        auto stmt = prepare_sql_statement(statement, argp);

        va_end(argp);

        int rc = sqlite3_step(stmt.get());
        if (rc != SQLITE_ROW) {
            if (rc == SQLITE_BUSY || rc == SQLITE_DONE) {
                return std::nullopt;
            }

            throw SQLGenericError(_db, stmt);
        }

        int integer = sqlite3_column_int(stmt.get(), 0);
        return std::optional<int> { integer };
    }

    std::vector<std::string> execute_sql_select_strings_statement(const char *statement, ...) {
        va_list argp;
        va_start(argp, statement);

        auto stmt = prepare_sql_statement(statement, argp);

        va_end(argp);

        std::vector<std::string> result;

        int rc;
        
        while ((rc = sqlite3_step(stmt.get())) == SQLITE_ROW) {
            auto row = sqlite3_column_text(stmt.get(), 0);
            result.emplace_back(reinterpret_cast<const char*>(row));
            // sqlite3_column_bytes(stmt.get(), 0);
        }

        if (rc != SQLITE_DONE) {
            if (rc == SQLITE_BUSY) {
                throw SQLBusyError(_db, stmt);
            } else if (rc == SQLITE_DONE) {
                throw SQLNotFoundError(_db, stmt);
            }

            throw SQLGenericError(_db, stmt);
        }

        return result;
    }
public:
    SQLiteDatabaseAccessObject(const std::string &database) {
        sqlite3 *db_handle;
        int rc;

        if (database.length() == 0) {
            rc = sqlite3_open_v2(":memory:", &db_handle, SQLITE_OPEN_READWRITE | SQLITE_OPEN_MEMORY, nullptr);
        } else {
            rc = sqlite3_open_v2(database.c_str(), &db_handle, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
        }

        if (rc != SQLITE_OK || db_handle == nullptr) {
            throw std::runtime_error(std::to_string(rc));
        } else {
            _db = SQLiteHandle(db_handle);
        }

        execute_sql_statement(
            "CREATE TABLE IF NOT EXISTS pages (\n"
            "    id INTEGER PRIMARY KEY,\n"
            "    url TEXT UNIQUE NOT NULL,\n"
            "    visited TEXT,\n"
            "    md5 TEXT\n"
            ");"
        );

        execute_sql_statement(
            "CREATE TABLE IF NOT EXISTS links (\n"
            "    id INTEGER PRIMARY KEY,\n"
            "    from_id INTEGER NOT NULL,\n"
            "    to_id INTEGER NOT NULL,\n"
            "    UNIQUE(from_id, to_id),\n"
            "    FOREIGN KEY (from_id)\n"
            "        REFERENCES pages (id),\n"
            "    FOREIGN KEY (to_id)\n"
            "        REFERENCES pages (id)\n"
            ");"
        );
    }

    // void insert_page(const std::string_view &url) {
    //     execute_sql_statement("INSERT INTO pages(url) VALUES(\"%s\");", url);
    // }

    bool page_in_database(const std::string &url) {
        const auto id = execute_sql_select_int_statement("SELECT id FROM pages WHERE url=(\"%s\");", url.c_str());

        if (id) {
            return true;
        }

        return false;
    }

    void insert_page(const std::string &url) {
        execute_sql_statement("INSERT INTO pages(url) VALUES(\"%s\");", url.c_str());
    }

    void link_pages(const std::string &url1, const std::string &url2) {
        const auto id1 = execute_sql_select_int_statement("SELECT id FROM pages WHERE url=(\"%s\");", url1.c_str());
        const auto id2 = execute_sql_select_int_statement("SELECT id FROM pages WHERE url=(\"%s\");", url2.c_str());
        if (id1 && id2) {
            execute_sql_statement("INSERT INTO links (from_id, to_id) VALUES(%d, %d);", id1, id2);
        }
        
    }

    void update_page_md5(const std::string &url, std::string page) {
        auto md5 = md5sum(page);
        const auto id = execute_sql_select_int_statement("SELECT id FROM pages WHERE url=(\"%s\");", url.c_str());

        if (id) {
            execute_sql_statement("UPDATE pages SET (visited, md5)=(date(), \"%s\") WHERE id=(%d);", md5.c_str(), id);
        }
    }

    std::vector<std::string> get_leaves() {
        return execute_sql_select_strings_statement("SELECT url FROM pages WHERE id NOT in (SELECT from_id FROM links);");
    }

    // get all child links and make a queue out of them so the crawler can restart
};


template <size_t MaxConcurrentConnections>
class CURLMultiHandler {
private:
    CURLMHandle _multi;
    SQLiteDatabaseAccessObject &_dao;
    std::mutex mtx;
    std::array<std::string, MaxConcurrentConnections> _buffers = {};
    std::array<CURLHandle, MaxConcurrentConnections> _handles = {};
    std::array<CURLUHandle, MaxConcurrentConnections> _urls = {};
    std::queue<size_t> _available_indices = {};

    std::queue<std::string> _pending_urls = {};
public:
    CURLMultiHandler(SQLiteDatabaseAccessObject &dao) : _dao(dao) {
        _multi = CURLMHandle(curl_multi_init());
        // for (auto &&buffer : _buffers) {
        //     buffer.reserve(1024 * 1024 * 4);
        // }

        for (size_t i = 0; i < MaxConcurrentConnections; i++) {
            _available_indices.push(i);
        }
    }

    void add_url(const std::string &url) {
        // std::lock_guard<std::mutex> guard(mtx);

        if (_available_indices.size() == 0) {
            _pending_urls.push(url);
            return;
        }

        size_t index = _available_indices.front();
        _available_indices.pop();

        _handles[index] = CURLHandle(curl_easy_init());
        _urls[index] = CURLUHandle(curl_url());
        _buffers[index] = std::string {};
        _buffers[index].reserve(1024 * 1024 * 4);

        auto &handle = _handles[index];
        auto &url_handle = _urls[index];
        auto &buffer = _buffers[index];

        auto rc = curl_url_set(url_handle.get(), CURLUPART_URL, url.c_str(), 0);
        if (rc != CURLUE_OK) {
            throw std::runtime_error(url);
        }

        curl_easy_setopt(handle.get(), CURLOPT_VERBOSE, verbose_flag);
        curl_easy_setopt(handle.get(), CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
        curl_easy_setopt(handle.get(), CURLOPT_HTTPGET, 1);
        curl_easy_setopt(handle.get(), CURLOPT_URL, url.c_str());

        curl_easy_setopt(handle.get(), CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36");

        curl_easy_setopt(handle.get(), CURLOPT_WRITEFUNCTION, &write_callback);
        curl_easy_setopt(handle.get(), CURLOPT_WRITEDATA, &buffer);

        curl_easy_setopt(handle.get(), CURLOPT_PRIVATE, index);

        curl_easy_setopt(handle.get(), CURLOPT_FOLLOWLOCATION, 1);
        curl_easy_setopt(handle.get(), CURLOPT_TIMEOUT, 10);
        curl_easy_setopt(handle.get(), CURLOPT_CONNECTTIMEOUT, 5);

        curl_multi_add_handle(_multi.get(), handle.get());
    }

    std::vector<std::pair<CURLUHandle, std::string>> run() {
        std::vector<std::pair<CURLUHandle, std::string>> results;
        int still_running = 1;
        int messages = 0;

        do {
            while (_available_indices.size() != 0 && _pending_urls.size() > 0) {
                add_url(_pending_urls.front());
                _pending_urls.pop();
            }

            CURLMcode mc = curl_multi_perform(_multi.get(), &still_running);

            // read all messages on the message stack
            CURLMsg *message;
            while ((message = curl_multi_info_read(_multi.get(), &messages)) != nullptr) {
                long response_code;
                size_t handle_index;

                if (message->msg == CURLMSG_DONE) {
                    if (curl_easy_getinfo(message->easy_handle, CURLINFO_RESPONSE_CODE, &response_code) == CURLE_OK) {
                        // std::cout << response_code << '\n';
                    }

                    if (response_code == 200 && curl_easy_getinfo(message->easy_handle, CURLINFO_PRIVATE, &handle_index) == CURLE_OK) {
                        // need to process before pushing the index back or else the buffer just gets overwritten lol
                        std::cout << handle_index << ": got response of " << _buffers[handle_index].size() << " bytes" << std::endl;
                        if (_buffers[handle_index].size() == 0) {
                            _available_indices.push(handle_index);
                            continue;
                        }

                        auto &url = _urls[handle_index];
                        char *url_buffer;
                        auto rc = curl_url_get(url.get(), CURLUPART_URL, &url_buffer, 0);
                        std::string url_str(url_buffer);
                        curl_free(url_buffer);

                        try {
                            _dao.insert_page(url_str);
                            std::cout << "saving " << url_str << std::endl;
                        } catch (SQLConstraintError &e) {
                            // std::cerr << e.what() << std::endl;
                        } catch (SQLError &e) {
                            std::cerr << e.what() << std::endl;
                            exit(1);
                        }

                        for (auto &&href : get_hrefs(_buffers[handle_index])) {
                            if (_dao.page_in_database(href.c_str())) {
                                continue;
                            }
                            // std::cout << href << "\n";
                            auto new_url = CURLUHandle(curl_url_dup(url.get()));
                            curl_url_set(new_url.get(), CURLUPART_URL, href.c_str(), 0);
                            char *url2;
                            curl_url_get(new_url.get(), CURLUPART_URL, &url2, 0);

                            std::string href_str(url2);
                            add_url(href_str);
                            curl_free(url2);

                            try {
                                _dao.insert_page(href_str);
                                _dao.link_pages(url_str, href_str);
                            } catch (SQLConstraintError &e) {
                                // std::cerr << e.what() << std::endl;
                            } catch (SQLError &e) {
                                std::cerr << e.what() << std::endl;
                                exit(2);
                            }
                        }

                        // results.push_back(std::pair(std::move(_urls[handle_index]), std::move(_buffers[handle_index])));

                        _available_indices.push(handle_index);
                        std::cout << "returning index " << handle_index << " to queue." << std::endl;
                    } else {
                        _available_indices.push(handle_index);
                        std::cout << handle_index << " returned " << response_code << std::endl;
                    }
                } else {
                    std::cout << "uhhmmmm?!!\n";
                }
            }

            if(!mc && still_running) {
                /* wait for activity, timeout or "nothing" */
                mc = curl_multi_poll(_multi.get(), nullptr, 0, 1000, nullptr);
            }

            if(mc) {
                fprintf(stderr, "curl_multi_poll() failed, code %d.\n", (int) mc);
                break;
            }

            /* if there are still transfers, loop! */
        } while(still_running || _pending_urls.size() > 0 || _available_indices.size() != MaxConcurrentConnections);

        return results;
    }
};


int main(int argc, char *argv[]) {
    curl_global_init(CURL_GLOBAL_DEFAULT);

    int c = 0;
    std::string database = "";
    std::string starting_url = "";

    while (c != -1) {
        int option_index = 0;
        c = getopt_long (argc, argv, "hvd:u:", long_options, &option_index);

        switch(c) {
        case 'h':
            std::cout << "Usage: " << argv[0] << " -d <DATABASE_NAME> -u <STARTING_URL>" << std::endl;
            return 0;
        case 'd':
            database = std::string(optarg);
            break;
        case 'u':
            starting_url = std::string(optarg);
            break;
        case 'v':
            verbose_flag = 1;
            break;
        }
    }

    if (optind < argc) {
        std::cerr << "Error: unknown command-line arguments: '";
        while (optind < argc) {
            std::cerr << argv[optind++] << ',';
        }
        std::cerr << "'\n";
        return 1;
    }

    auto dao = SQLiteDatabaseAccessObject(database);
    auto multi = CURLMultiHandler<256>(dao);

    std::deque<std::string> url_queue;

    // using multi:
    // multi.add_url(...)
    // repeat multiple times
    // multi.run() to execute requests in parallel

    if (starting_url.length() != 0) {
        // starting_url = "https://en.wikipedia.org/wiki/SHA-2";
        url_queue.push_back(starting_url);
    }

    if (database.length() != 0) {
        std::cout << "Using " << database << '\n';
        auto leaves = dao.get_leaves();

        if (leaves.size() == 0) {
            url_queue.push_back(starting_url);
        } else {
            for (auto &&leaf : leaves) {
                url_queue.push_back(leaf);
            }
        }
    }

    while (url_queue.size()) {
        for (unsigned int pushed_urls = 0; (pushed_urls < 64) && (url_queue.size() > 0); pushed_urls++) {
            auto url = url_queue.front();
            multi.add_url(url);

            try {
                dao.insert_page(url);
            } catch (SQLConstraintError &e) {
                std::cerr << e.what() << std::endl;
            } catch (SQLError &e) {
                std::cerr << e.what() << std::endl;
                return 1;
            }
            
            url_queue.pop_front();
        }

        auto pages = multi.run();

        for (auto &&page : pages) {
            char *url;

            curl_url_get(page.first.get(), CURLUPART_URL, &url, 0);
            std::string parent_url(url);
            
            
            try {
                dao.insert_page(url);
            } catch (SQLError &e) {
                dao.update_page_md5(parent_url, page.second);
                return 1;
            }

            auto hrefs = get_hrefs(page.second);

            for (auto &&href : hrefs) {
                auto new_url = CURLUHandle(curl_url_dup(page.first.get()));
                curl_url_set(new_url.get(), CURLUPART_URL, href.c_str(), 0);

                char *url2;
                curl_url_get(new_url.get(), CURLUPART_URL, &url2, 0);
                url_queue.emplace_back(url2);

                try {
                    dao.insert_page(url2);
                    dao.link_pages(parent_url, url2);
                } catch (SQLConstraintError &e) {
                    std::cerr << e.what() << std::endl;
                } catch (SQLError &e) {
                    std::cerr << e.what() << std::endl;
                    return 1;
                }

                curl_free(url2);
            }

            curl_free(url);
        }
    }

    return 0;
}
