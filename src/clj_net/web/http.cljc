(ns clj-net.web.http
  (:require [clj-lang-extra.core :refer [hex->int int->hex]]
            [clojure.string :as str]
            [clj-bytes.core :as b]
            [clj-bytes.struct :as st]))

(defn get-header
  "Get value from headers."
  [headers k]
  (let [k (cond-> k (keyword? k) name)
        k (str/lower-case k)]
    (->> headers
         (filter
          (fn [header]
            (= k (-> header first str/lower-case))))
         first)))

^:rct/test
(comment
  (get-header [["Host" "www.google.com"] ["Connection" "close"]] :host) ; => ["Host" "www.google.com"]
  (get-header [["Host" "www.google.com"] ["Connection" "close"]] "connection") ; => ["Connection" "close"]
  )

(defn str->header
  "Convert string to one header."
  [s]
  (let [[k v] (str/split s #":" 2)]
    (if (nil? v)
      (throw (ex-info "http key validation error" {:reason :struct-error}))
      [(str/trim k) (str/trim v)])))

(defn str->headers
  "Convert string to headers."
  [s]
  (->> (str/split s #"\r\n" -1) (mapv str->header)))

(defn header->str
  "Convert one header to string."
  [[k v]]
  (str k \: \space v))

(defn headers->str
  "Convert headers to string."
  [headers]
  (->> headers (map header->str) (str/join "\r\n")))

^:rct/test
(comment
  (str->headers "Host: google.com\r\nConnection: close") ; => [["Host" "google.com"] ["Connection" "close"]]
  (headers->str [["Host" "google.com"] ["Connection" "close"]]) ; => "Host: google.com\r\nConnection: close"
  )

(def req-line-re
  "HTTP request line regexp."
  #"^([a-zA-Z]+)\s+([^\s]+)\s+[Hh][Tt][Tt][Pp]/([0-9\.]+)$")

(defn str->req-line
  "Convert string to request line."
  [s]
  (if-let [[_s method path version] (re-matches req-line-re s)]
    [method path version]
    (throw (ex-info "http request line validation error" {:reason :struct-error}))))

(defn req-line->str
  "Convert request line to string."
  [[method path version]]
  (let [path (or path "/")
        version (or version "1.1")]
    (str method \space path \space "HTTP/" version)))

^:rct/test
(comment
  (str->req-line "GET / HTTP/1.1") ; => ["GET" "/" "1.1"]
  (req-line->str ["GET" "/" "1.1"]) ; => "GET / HTTP/1.1"
  (req-line->str ["GET"]) ; => "GET / HTTP/1.1"
  )

(def resp-line-re
  "HTTP response line regexp."
  #"^[Hh][Tt][Tt][Pp]/([0-9\.]+)\s+([0-9][0-9][0-9])\s+([a-zA-Z]+)$")

(defn str->resp-line
  "Convert string to response line."
  [s]
  (if-let [[_s version status reason] (re-matches resp-line-re s)]
    [version status reason]
    (throw (ex-info "http response line validation error" {:reason :struct-error}))))

(defn resp-line->str
  "Conert response line to string."
  [[version status reason]]
  (str "HTTP/" version \space status \space reason))

(def st-headers
  (-> (st/line "\r\n\r\n")
      (st/wrap headers->str str->headers)))

(def st-req-line
  (-> st/http-line
      (st/wrap req-line->str str->req-line)))

(def st-req
  (-> (st/keys
       :req-line st-req-line
       :headers st-headers)
      (st/wrap-vec-destructs
       {:req-line [:method :path :version]})
      (st/wrap-merge
       {:method "GET" :path "/" :version "1.1" :headers []})))

(def st-resp-line
  (-> st/http-line
      (st/wrap resp-line->str str->resp-line)))

(def st-resp
  (-> (st/keys
       :resp-line st-resp-line
       :headers st-headers)
      (st/wrap-vec-destructs
       {:resp-line [:version :status :reason]})
      (st/wrap-merge
       {:version "1.1" :status "200" :reason "OK" :headers []})))

^:rct/test
(comment
  (-> (b/of-str "GET / HTTP/1.1\r\nHost: google.com\r\n\r\n") (st/unpack-one st-req))
  ;; =>>
  {:method "GET" :path "/" :version "1.1" :headers [["Host" "google.com"]]}
  (-> (b/of-str "HTTP/1.1 200 OK\r\nHost: google.com\r\n\r\n") (st/unpack-one st-resp))
  ;; =>>
  {:version "1.1" :status "200" :reason "OK" :headers [["Host" "google.com"]]})

(def st-chunk
  (-> st/http-line
      (st/wrap int->hex hex->int)
      st/bytes-var))

^:rct/test
(comment
  (-> (b/of-str "5\r\nhello") (st/unpack-one st-chunk) b/str) ; => "hello"
  )
