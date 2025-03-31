(ns clj-net.inet.tcp
  (:require [clj-bytes.struct :as st]
            [clj-net.inet.packet :as pkt]))

;; RFC 9293 TCP
;; RFC 7323 TCP extensions
;; RFC 2018 TCP sack

(def st-tcp
  (-> (st/keys
       :sport st/uint16-be
       :dport st/uint16-be
       :seq st/uint32-be
       :ack st/uint32-be
       :dtaofs-res (st/bits [4 4])
       :cwr-ece-urg-ack-psh-rst-syn-fin (st/bits [1 1 1 1 1 1 1 1])
       :window st/uint16-be
       :chksum st/uint16-be
       :urgptr st/uint16-be
       :options (st/lazy #(st/bytes-fixed (* 4 (- (:dataofs %) 5)))))
      (st/wrap-vec-destructs
       {:dataofs-res [:dataofs :res]
        :cwr-ece-urg-ack-psh-rst-syn-fin [:cwr :ece :urg :ack :psh :rst :syn :fin]})))

(def tcp-option-map
  (st/->kimap {:eol 0 :nop 1 :mss 2 :wscale 3 :sack-ok 4 :sack 5 :timestamp 6}))

(def st-tcp-option
  (st/keys
   :type st/uint8
   :data (st/lazy
          (fn [{:keys [type]}]
            (case type
              (0 1) (st/bytes-fixed 0)
              (-> st/uint8
                  (st/wrap #(+ % 2) #(- % 2))
                  st/bytes-var))))))

(def st-tcp-option-mss
  st/uint16-be)

(def st-tcp-option-wscale
  st/uint8)

(def st-tcp-option-sack
  (st/coll-of st/uint32-be))

(def st-tcp-option-timestamp
  (st/keys
   :tsval st/uint32-be
   :tsecr st/uint16-be))

(def tcp-option-st-map
  {:mss st-tcp-option-mss
   :wscale st-tcp-option-wscale
   :sack st-tcp-option-sack
   :timestamp st-tcp-option-timestamp})

(defmulti parse-tcp-option
  (fn [option] (:type option)))

(defmethod parse-tcp-option :default [option] option)
(defmethod parse-tcp-option 0 [_option] {:type :eol})
(defmethod parse-tcp-option 1 [_option] {:type :eol})

(doseq [[k i] (:k->i tcp-option-map)]
  (when-not (contains? #{0 1} i)
    (if-let [st (get tcp-option-st-map k)]
      (defmethod parse-tcp-option i [option] (pkt/parse-option option k st))
      (defmethod parse-tcp-option i [option] (pkt/parse-option option k)))))

(defn parse-tcp-options
  [b]
  (->> (st/unpack-many b st-tcp-option)
       (mapv parse-tcp-option)))

(defmethod pkt/parse :tcp [type _context buffer]
  (pkt/parse-packet
   st-tcp type buffer
   (fn [{:keys [sport dport seq ack window options] :as data}]
     (let [flags (->> #{:cwr :ece :urg :ack :psh :rst :syn :fin} (remove #(zero? (get data %))) set)]
       {:data-extra {:flags flags :options (parse-tcp-options options)}
        :context-extra #:tcp{:sport sport :dport dport :seq seq :ack ack :window window :flags flags}}))))
