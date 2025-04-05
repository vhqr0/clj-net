(ns clj-net.inet.tcp
  (:require [clj-bytes.core :as b]
            [clj-bytes.struct :as st]
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
       :dataofs-res (st/bits [4 4])
       :flags (st/bits [1 1 1 1 1 1 1 1])
       :window st/uint16-be
       :chksum st/uint16-be
       :urgptr st/uint16-be
       :options (st/lazy #(st/bytes-fixed (* 4 (- (first (:dataofs-res %)) 5)))))
      (st/wrap-vec-destructs
       {:dataofs-res [:dataofs :res]
        :flags [:c :e :u :a :p :r :s :f]})
      (st/wrap-merge
       {:sport 0 :dport 80 :seq 0 :ack 0 :dtaofs 5 :res 0
        :c 0 :e 0 :u 0 :a 0 :p 0 :r 0 :s 1 :f 0
        :window 8192 :chksum 0 :urgptr 0 :options (b/empty)})))

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
                  (st/wrap-validator nat-int?)
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
(defmethod parse-tcp-option 1 [_option] {:type :nop})

(doseq [[k i] (:k->i tcp-option-map)]
  (when-not (contains? #{0 1} i)
    (let [st (get tcp-option-st-map k)]
      (defmethod parse-tcp-option i [option] (pkt/unpack-option st k option)))))

(defn parse-tcp-options
  [b]
  (->> (st/unpack-many b st-tcp-option)
       (mapv parse-tcp-option)))

(defmethod pkt/parse :tcp [type _context buffer]
  (pkt/unpack-packet
   st-tcp type buffer
   (fn [{:keys [sport dport seq ack window options] :as data}]
     (let [flags (->> #{:c :e :u :a :p :r :s :f} (remove #(zero? (get data %))) set)]
       {:data-extra {:flags flags :options (parse-tcp-options options)}
        :context-extra #:tcp{:sport sport :dport dport :seq seq :ack ack :window window :flags flags}}))))
