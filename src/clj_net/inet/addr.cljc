(ns clj-net.inet.addr
  (:require [clj-lang-extra.core :refer [str->int hex->int int->hex]]
            [clojure.string :as str]
            [clj-bytes.core :as b]
            [clj-bytes.struct :as st]))

(defprotocol Addr
  (-str [_])
  (-bytes [_]))

(defmulti of-str
  "Convert str to addr."
  (fn [type _s] type))

(defmulti of-bytes
  "Convert type to addr."
  (fn [type _s] type))

(defn bytes->str
  "Convert addr in bytes to str."
  [type b]
  (-> (of-bytes type b) -str))

(defn str->bytes
  "Convert addr in str to bytes."
  [type s]
  (-> (of-str type s) -bytes))

;;; utils

(defn- fill-zeros
  "Left fill str with zeros to cnt."
  [s cnt]
  {:pre [(<= (count s) cnt)]}
  (let [zeros-cnt (- cnt (count s))]
    (if (zero? zeros-cnt)
      s
      (let [zeros (->> (repeat zeros-cnt \0) str/join)]
        (str zeros s)))))

(defn- longest-connected-zeros
  "Get the longest connected zeros in int seq, return the first index and length."
  [ints]
  (when-let [connects (->> ints
                           (map-indexed vector)
                           (partition-by second)
                           (filter #(zero? (second (first %))))
                           seq)]
    ;; NOTICE use reverse before max-key
    (let [connect (->> connects reverse (apply max-key count))]
      [(ffirst connect) (count connect)])))

^:rct/test
(comment
  (longest-connected-zeros [1 2 0 3 4 0 0 0 5 6 0 0 7]))

;;; mac

(defrecord MACAddr [segs]
  Addr
  (-str [_]
    (->> segs (map #(-> % int->hex (fill-zeros 2))) (str/join \:)))
  (-bytes [_]
    (b/of-useq segs)))

(defn- ->mac
  [segs]
  {:pre [(= (count segs) 6)]}
  (->MACAddr segs))

(defmethod of-str :mac [_type s]
  (let [s (str/replace s "-" ":")]
    (->> (str/split s #":") (mapv hex->int) ->mac)))

(defmethod of-bytes :mac [_type b]
  {:pre [(= (b/count b) 6)]}
  (->> (b/useq b) vec ->mac))

^:rct/test
(comment
  (b/equal? (str->bytes :mac "33:33:00:00:00:01") (b/of-seq [51 51 0 0 0 1])) ; => true
  (bytes->str :mac (b/of-seq [51 51 0 0 0 1])) ; => "33:33:00:00:00:01"
  )

;;; ipv4

(defrecord IPv4Addr [segs]
  Addr
  (-str [_]
    (->> segs (map str) (str/join \.)))
  (-bytes [_]
    (b/of-useq segs)))

(defn- ->ipv4
  [segs]
  {:pre [(= (count segs) 4)]}
  (->IPv4Addr segs))

(defmethod of-str :ipv4 [_type s]
  (->> (str/split s #"\.") (map str->int) ->ipv4))

(defmethod of-bytes :ipv4 [_type b]
  {:pre [(= (b/count b) 4)]}
  (->> (b/useq b) vec ->ipv4))

^:rct/test
(comment
  (b/equal? (str->bytes :ipv4 "192.168.0.1") (b/of-seq [192 168 0 1])) ; => true
  (bytes->str :ipv4 (b/of-seq [192 168 0 1])) ; => "192.168.0.1"
  )

;;; ipv6

(defrecord IPv6Addr [segs]
  Addr
  (-str [_]
    (if-let [[i c] (longest-connected-zeros segs)]
      (let [lsegs (->> segs (take i) (map int->hex) (str/join \:))
            rsegs (->> segs (drop (+ i c)) (map int->hex) (str/join \:))]
        (str lsegs "::" rsegs))
      (->> segs (map int->hex) (str/join \:))))
  (-bytes [_]
    (->> segs
         (mapcat
          (fn [i]
            [(bit-shift-right i 8) (bit-and i 0xff)]))
         b/of-useq)))

(defn- ->ipv6
  [segs]
  {:pre [(= (count segs) 8)]}
  (->IPv6Addr segs))

(defmethod of-str :ipv6 [_type s]
  (let [sp (cond-> (str/split s #"::")
             ;; NOTICE str/split will pop trailling whitespace
             (str/ends-with? s "::") (conj ""))]
    (case (count sp)
      1 (->> (str/split s #":") (mapv hex->int) ->ipv6)
      2 (let [[ls rs] sp
              ls (when (seq ls) (->> (str/split ls #":") (map hex->int)))
              rs (when (seq rs) (->> (str/split rs #":") (map hex->int)))
              zeros-cnt (- 8 (count ls) (count rs))]
          (->> (concat ls (repeat zeros-cnt 0) rs) vec ->ipv6)))))

(defmethod of-bytes :ipv6 [_type b]
  [{:pre [(= (b/count b) 16)]}]
  (->> (b/useq b)
       (partition 2)
       (mapv
        (fn [[l r]]
          (+ (bit-shift-left l 8) r)))
       ->ipv6))

^:rct/test
(comment
  (b/equal? (str->bytes :ipv6 "::1") (b/of-seq [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1])) ; => true
  (b/equal? (str->bytes :ipv6 "2000::") (b/of-seq [32 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0])) ; => true
  (b/equal? (str->bytes :ipv6 "2000::1") (b/of-seq [32 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1])) ; => true
  (b/equal? (str->bytes :ipv6 "2000:0:0:0:1:0:0:1") (b/of-seq [32 0 0 0 0 0 0 0 0 1 0 0 0 0 0 1])) ; => true
  (bytes->str :ipv6 (b/of-seq [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1])) ; => "::1"
  (bytes->str :ipv6 (b/of-seq [32 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0])) ; => "2000::"
  (bytes->str :ipv6 (b/of-seq [32 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1])) ; => "2000::1"
  (bytes->str :ipv6 (b/of-seq [32 0 0 0 0 0 0 0 0 1 0 0 0 0 0 1])) ; => "2000::1:0:0:1"
  )

;;; structs

(defn st-addr
  "Construct addr struct."
  [type length]
  (-> (st/bytes-fixed length)
      (st/wrap
       (partial str->bytes type)
       (partial bytes->str type))))

(def st-mac "MAC addr struct." (st-addr :mac 6))
(def st-ipv4 "IPv4 addr struct." (st-addr :ipv4 4))
(def st-ipv6 "IPv6 addr struct." (st-addr :ipv6 16))

^:rct/test
(comment
  (-> (b/make 6) (st/unpack-one st-mac)) ; => "00:00:00:00:00:00"
  )
