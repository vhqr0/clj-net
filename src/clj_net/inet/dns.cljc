(ns clj-net.inet.dns
  (:require [clojure.string :as str]
            [clj-bytes.core :as b]
            [clj-bytes.struct :as st]
            [clj-net.inet.addr :as ia]
            [clj-net.inet.packet :as pkt]))

;; RFC 1035 DNS
;; RFC 3596 DNS AAAA

(defmethod st/pack :clj-net.inet/dns-name [d _st]
  (let [ds (if-not (string? d)
             d
             (str/split d #"\."))]
    (loop [bs [] ds ds]
      (if (empty? ds)
        (b/join! (conj bs (-> 0 (st/pack st/uint8))))
        (let [d (first ds)]
          (if (string? d)
            (let [b (b/of-str d)
                  c (-> (b/count b) (st/pack st/uint8))]
              (recur (conj bs c b) (rest ds)))
            (let [b (-> (+ 0xc000 d) (st/pack st/uint16-be))]
              (b/join! (conj bs b)))))))))

(defmethod st/unpack :clj-net.inet/dns-name [b _st]
  (loop [ds [] b b]
    (when-let [[c b] (-> b (st/unpack st/uint8))]
      (cond
        ;; zero end
        (zero? c)
        [(str/join \. ds) b]
        ;; pointer end
        (= (bit-and c 0xc0) 0xc0)
        (when-let [[r b] (-> b (st/unpack st/uint8))]
          (let [c (+ (bit-shift-left (bit-and c 0x3f) 8) r)]
            [(conj ds c) b]))
        ;; non-end
        :else
        (let [st (-> (st/bytes-fixed c) st/wrap-str)]
          (when-let [[d b] (-> b (st/unpack st))]
            (recur (conj ds d) b)))))))

(def st-dns-name
  {:type :clj-net.inet/dns-name})

^:rct/test
(comment
  (b/equal? (-> "google.com" (st/pack st-dns-name))
            (b/concat!
             (b/of-useq [6]) (b/of-str "google")
             (b/of-useq [3]) (b/of-str "com")
             (b/of-useq [0])))
  ;; => true
  (-> (b/concat!
       (b/of-useq [6]) (b/of-str "google")
       (b/of-useq [3]) (b/of-str "com")
       (b/of-useq [0]))
      (st/unpack-one st-dns-name))
  ;; => "google.com"
  (b/equal? (-> ["google" 20] (st/pack st-dns-name))
            (b/concat! (b/of-useq [6]) (b/of-str "google") (b/of-useq [0xc0 20])))
  ;; => true
  (-> (b/concat! (b/of-useq [6]) (b/of-str "google") (b/of-useq [0xc0 20]))
      (st/unpack-one st-dns-name))
  ;; => ["google" 20]
  )

(def dns-type-map
  (st/->kimap
   {:a      1
    :ns     2
    :md     3
    :mf     4
    :cname  5
    :soa    6
    :mb     7
    :mg     8
    :mr     9
    :null  10
    :wks   11
    :ptr   12
    :hinfo 13
    :minfo 14
    :mx    15
    :txt   16
    :aaaa  28}))

(def dns-class-map
  (st/->kimap {:in 1}))

(def st-dns-rr
  (st/keys
   :name st-dns-name
   :type st/uint16-be
   :class st/uint16-be
   :ttl st/uint32-be
   :data (st/bytes-var st/uint16-be)))

(def st-dns-qr
  (st/keys
   :name st-dns-name
   :type st/uint16-be
   :class st/uint16-be))

(def st-dns
  (-> (st/keys
       :id st/uint16-be
       :qr-opcode-aa-tc-rd-ra-z-ad-ac-rcode (st/bits [1 4 1 1 1 1 1 1 1 4])
       :qdcount st/uint16-be
       :ancount st/uint16-be
       :nscount st/uint16-be
       :arcount st/uint16-be
       :qd (st/lazy #(st/coll-of (:qdcount %) st-dns-qr))
       :an (st/lazy #(st/coll-of (:ancount %) st-dns-rr))
       :ns (st/lazy #(st/coll-of (:nscount %) st-dns-rr))
       :ar (st/lazy #(st/coll-of (:arcount %) st-dns-rr)))
      (st/wrap-vec-destructs
       {:qr-opcode-aa-tc-rd-ra-z-ad-ac-rcode [:qr :opcode :aa :tc :rd :ra :z :ad :ac :rcode]})))

(def st-dns-rr-cname
  st-dns-name)

(def st-dns-rr-ns
  st-dns-name)

(def st-dns-rr-ptr
  st-dns-name)

(def st-dns-rr-a
  ia/st-ipv4)

(def st-dns-rr-aaaa
  ia/st-ipv6)

(def st-dns-rr-txt
  st/str)

(def st-dns-rr-soa
  (st/keys
   :mname st-dns-name
   :rname st-dns-name
   :serial st/uint32-be
   :refresh st/uint32-be
   :retry st/uint32-be
   :expire st/uint32-be
   :minimum st/uint32-be))

(def st-dns-rr-mx
  (st/keys
   :preference st/uint16-be
   :exchange st-dns-name))

(def dns-rr-st-map
  {:cname st-dns-rr-cname
   :ns st-dns-rr-ns
   :ptr st-dns-rr-ptr
   :a st-dns-rr-a
   :aaaa st-dns-rr-aaaa
   :txt st-dns-rr-txt
   :mx st-dns-rr-mx
   :soa st-dns-rr-soa})

(defmulti parse-dns-rr
  (fn [option] (:type option)))

(defmethod parse-dns-rr :default [option] option)

(doseq [[k i] (:k->i dns-type-map)]
  (let [st (get dns-rr-st-map k)]
    (defmethod parse-dns-rr i [option] (pkt/unpack-option st k option))))

(defmethod pkt/parse :dns [type _context buffer]
  (pkt/unpack-packet
   st-dns type buffer
   (fn [{:keys [an ns ar]}]
     (let [an (->> an (mapv parse-dns-rr))
           ns (->> ns (mapv parse-dns-rr))
           ar (->> ar (mapv parse-dns-rr))]
       {:data-extra {:an an :ns ns :ar ar :buffer :buffer}}))))
