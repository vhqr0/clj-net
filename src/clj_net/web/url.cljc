(ns clj-net.web.url
  (:require [clj-lang-extra.core :refer [str->int]]
            [clojure.string :as str]))

(defn get-query
  [query k]
  (->> query (filter #(= k (first %))) (mapv second)))

^:rct/test
(comment
  (get-query [["a" "1"] ["b" "2"] ["a" "3"]] "a") ; => ["1" "3"]
  )

(defn str->query-1
  [s]
  (let [[k v] (str/split s #"=" 2)]
    [(str/trim k) (str/trim (or v ""))]))

(defn str->query
  [s]
  (->> (str/split s #"&" -1) (mapv str->query-1)))

(defn query-1->str
  [[k v]]
  (str k \= v))

(defn query->str
  [query]
  (->> query (map query-1->str) (str/join "&")))

^:rct/test
(comment
  (str->query "a=1&b=2") ; => [["a" "1"] ["b" "2"]]
  (query->str [["a" "1"] ["b" "2"]]) ; => "a=1&b=2"
  )

(def url-re #"^([a-zA-Z0-9+-\.]+)://(([^@:]*)(:([^@]*))?@)?(\[[0-9a-fA-F:]*\]|[^:/?#]*)(:([0-9]+))?(/[^?#]*)?(\?([^#]*))?(#(.*))?$")

^:rct/test
(comment
  (re-matches url-re "http://") ; => ["http://" "http" nil nil nil nil "" nil nil nil nil nil nil nil]
  (re-matches url-re "http://google.com") ; => ["http://google.com" "http" nil nil nil nil "google.com" nil nil nil nil nil nil nil]
  (re-matches url-re "http://user@google.com") ; => ["http://user@google.com" "http" "user@" "user" nil nil "google.com" nil nil nil nil nil nil nil]
  (re-matches url-re "http://user:123@google.com") ; => ["http://user:123@google.com" "http" "user:123@" "user" ":123" "123" "google.com" nil nil nil nil nil nil nil]
  (re-matches url-re "http://google.com/index.html") ; => ["http://google.com/index.html" "http" nil nil nil nil "google.com" nil nil "/index.html" nil nil nil nil]
  (re-matches url-re "http://google.com:80/index.html") ; => ["http://google.com:80/index.html" "http" nil nil nil nil "google.com" ":80" "80" "/index.html" nil nil nil nil]
  (re-matches url-re "http://google.com:80/index.html?a=1&b=2#head") ; => ["http://google.com:80/index.html?a=1&b=2#head" "http" nil nil nil nil "google.com" ":80" "80" "/index.html" "?a=1&b=2" "a=1&b=2" "#head" "head"]
  (re-matches url-re "http://[2000::1]:80") ; => ["http://[2000::1]:80" "http" nil nil nil nil "[2000::1]" ":80" "80" nil nil nil nil nil]
  )

(defn str->url
  [s]
  (if-let [[_s schema _user-info username _passwrod-group password host _port-group port path _query-group query _fragment-group fragment] (re-matches url-re s)]
    (cond-> {:schema schema :host host}
      (some? port)     (assoc :port (str->int port))
      (some? username) (assoc :username username)
      (some? password) (assoc :password password)
      (some? path)     (assoc :path path)
      (some? query)    (assoc :query (str->query query))
      (some? fragment) (assoc :fragment fragment))
    (throw (ex-info "url validation error" {:reason :struct-error}))))

^:rct/test
(comment
  (str->url "http://") ; => {:schema "http" :host ""}
  (str->url "http://google.com") ; => {:schema "http" :host "google.com"}
  (str->url "http://user@google.com") ; => {:schema "http" :host "google.com" :username "user"}
  (str->url "http://user:123@google.com") ; => {:schema "http" :host "google.com" :username "user" :password "123"}
  (str->url "http://google.com/index.html") ; => {:schema "http" :host "google.com" :path "/index.html"}
  (str->url "http://google.com:80/index.html") ; => {:schema "http" :host "google.com" :port 80 :path "/index.html"}
  (str->url "http://google.com:80/index.html?a=1&b=2#head") ; => {:schema "http" :host "google.com" :port 80 :path "/index.html" :query [["a" "1"] ["b" "2"]] :fragment "head"}
  (str->url "http://[2000::1]:80") ; => {:schema "http" :host "[2000::1]" :port 80}
  )

(defn url->str
  [{:keys [schema host port username password path query fragment] :or {schema "http"}}]
  (str schema "://"
       username
       (when (some? password) (str \: password))
       (when (or (some? username) (some? password)) \@)
       host
       (when (some? port) (str \: port))
       path
       (when (some? query) (str \? (query->str query)))
       (when (some? fragment) (str \# fragment))))

^:rct/test
(comment
  (url->str {}) ; => "http://"
  (url->str {:schema "http" :username "user" :password "123" :host "google.com" :port 80 :path "/index.html"})
  ;; => "http://user:123@google.com:80/index.html"
  (url->str {:schema "http" :username "user" :password "123" :host "google.com" :port 80 :path "/index.html" :query [["a" "1"] ["b" "2"]] :fragment "head"})
  ;; => "http://user:123@google.com:80/index.html?a=1&b=2#head"
  )
