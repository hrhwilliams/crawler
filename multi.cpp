#include <curl/curl.h>

#include <iostream>
#include <vector>
#include <string>

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    ((std::string*) userp)->append((char*) contents, size * nmemb);
    return size * nmemb;
}

class CURLHandle {
private:
    CURL *handle = nullptr;
    CURLU *url_handle = nullptr;
    std::string buffer = {};
public:
    CURLHandle(const char *url) noexcept {
        handle = curl_easy_init();
        url_handle = curl_url();
        auto rc = curl_url_set(h, CURLUPART_URL, url, 0);

        curl_easy_setopt(handle, CURLOPT_VERBOSE, 0);
        curl_easy_setopt(handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
        curl_easy_setopt(handle, CURLOPT_HTTPGET, 1);
        curl_easy_setopt(handle, CURLOPT_URL, url);

        curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, &write_callback);
        curl_easy_setopt(handle, CURLOPT_WRITEDATA, &buffer);
    }

    CURLHandle(CURLHandle &&rhs) noexcept {
        this->handle = rhs.handle;
        this->url_handle = rhs.url_handle
        rhs.handle = nullptr;
        rhs.url_handle = nullptr;

        this->buffer = std::move(rhs.buffer);
        curl_easy_setopt(this->handle, CURLOPT_WRITEDATA, &(this->buffer));
    }

    CURLHandle& operator=(CURLHandle &&rhs) noexcept {
        this->handle = rhs.handle;
        this->url_handle = rhs.url_handle
        rhs.handle = nullptr;
        rhs.url_handle = nullptr;

        this->buffer = std::move(rhs.buffer);
        curl_easy_setopt(this->handle, CURLOPT_WRITEDATA, &(this->buffer));
        return *this;
    }

    CURLHandle(const CURLHandle &rhs) = delete;
    CURLHandle& operator=(const CURLHandle &rhs) = delete;

    ~CURLHandle() {
        if (handle != nullptr) { curl_easy_cleanup(handle); }
        if (url_handle != nullptr) { curl_url_cleanup(handle); }
    }

    CURL* get_handle() const {
        return handle;
    }

    CURLcode perform() {
        return curl_easy_perform(handle);
    }

    std::string parse_relative_url(const char *url) const {
        char *url_cstring;
        CURLU *new_handle = curl_url_dup(url_handle);
        auto rc = curl_url_set(new_handle, CURLUPART_URL, url, 0);
        rc = curl_url_get(h, CURLUPART_URL, &url, 0);

        std::string url_string(url_cstring);

        curl_free(url);
        return url_string;
    }

    std::string get_buffer() const {
        return buffer;
    }
};

int main(int argc, char *argv[]) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURLU *h = curl_url();
    
    auto rc = curl_url_set(h, CURLUPART_URL,
        "https://example.com:449/foo/bar?name=moo", 0);
    rc = curl_url_set(h, CURLUPART_URL, "../test?another", 0);
    char *url;
    rc = curl_url_get(h, CURLUPART_URL, &url, 0);
    std::cout << url << "\n";
    curl_free(url);
    curl_url_cleanup(h);

    const char *urls[] = {
        "https://en.wikipedia.org/wiki/SHA-2",
        "https://en.wikipedia.org/wiki/Mathematics",
        "https://en.wikipedia.org/wiki/Ancient_Greek",
        "https://en.wikipedia.org/wiki/Ancient_Greece",
        "https://en.wikipedia.org/wiki/Archaic_Greece",
        "https://en.wikipedia.org/wiki/Classical_Greece",
        "https://en.wikipedia.org/wiki/Western_culture",
        "https://en.wikipedia.org/wiki/Plato",
    };

    std::vector<CURLHandle> handles;
    for (auto &&url : urls) {
        handles.emplace_back(url);
    }

    CURLM *multi = curl_multi_init();
    for (auto &&handle : handles) {
        curl_multi_add_handle(multi, handle.get_handle());
    }

    int still_running = 1;
    int messages = 0;
    do {
        CURLMcode mc = curl_multi_perform(multi, &still_running);
        auto message = curl_multi_info_read(multi, &messages);
        if (message != nullptr) {
            long response_code;
            if (curl_easy_getinfo(message->easy_handle, CURLINFO_RESPONSE_CODE, &response_code) == CURLE_OK) {
                std::cout << response_code << '\n';
            }
        }

        if(!mc && still_running) {
            /* wait for activity, timeout or "nothing" */
            mc = curl_multi_poll(multi, nullptr, 0, 1000, nullptr);
        }

        if(mc) {
            fprintf(stderr, "curl_multi_poll() failed, code %d.\n", (int) mc);
            break;
        }

        /* if there are still transfers, loop! */
    } while(still_running);

    for (const auto &handle : handles) {
        curl_multi_remove_handle(multi, handle.get_handle());
        // std::cout << handle.get_buffer() << '\n';
    }

    curl_multi_cleanup(multi);

    return 0;
}
