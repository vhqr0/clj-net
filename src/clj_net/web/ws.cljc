(ns clj-net.web.ws
  (:require [clj-bytes.core :as b]
            [clj-bytes.struct :as st]))

;; RFC 6455

(defn mask-data!
  "Mask data, impure."
  [data key]
  (doseq [i (b/count data)]
    (b/uset! data i (bit-xor (b/uget data i) (b/uget key (mod i 4)))))
  data)

(defn mask-data
  "Mask data, pure."
  [data key]
  (mask-data! (b/sub data) key))

(def opcode-map
  (st/->kimap
   {:continue  0
    :text      1
    :binary    2
    :close     8
    :ping      9
    :pong     10}))

(def st-frame-header
  (-> (st/keys
       :fin-rsv-opcode-mask-len (st/bits [1 3 4 1 7])
       :elen (st/lazy
              (fn [{:keys [fin-rsv-opcode-mask-len]}]
                (let [[_fin _rsv _opcode _mask len] fin-rsv-opcode-mask-len]
                  (cond (< len 126) (st/bytes-fixed 0)
                        (< len 65536) (st/bytes-fixed 2)
                        :else (st/bytes-fixed 8)))))
       :key (st/lazy
             (fn [{:keys [fin-rsv-opcode-mask-len]}]
               (let [[_fin _rsv _opcode mask _len] fin-rsv-opcode-mask-len]
                 (if (zero? mask) (st/bytes-fixed 0) (st/bytes-fixed 4))))))
      (st/wrap-vec-destructs
       {:fin-rsv-opcode-mask-len [:fin :rsv :opcode :mask :len]})
      (st/wrap
       (fn [{:keys [len] :as d}]
         (let [[len elen] (cond (< len 126) [len (b/empty)]
                                (< len 65536) [126 (-> len (st/pack st/uint16-be))]
                                :else [127 (-> len (st/pack st/int64-be))])]
           (assoc d :len len :elen elen)))
       (fn [{:keys [len elen] :as d}]
         (let [len (cond (= len 126) (-> elen (st/unpack st/uint16-be))
                         (= len 127) (-> elen (st/unpack st/int64-be))
                         :else len)]
           (assoc d :len len))))
      (st/wrap-validator (comp nat-int? :len))))

(defn mask-st
  "Mask frame struct."
  [{:keys [header data]}]
  (let [{:keys [mask key]} header]
    (if (zero? mask)
      data
      (mask-data data key))))

(def st-frame
  (-> (st/keys
       :header st-frame-header
       :data (st/lazy
              (fn [{:keys [header]}]
                (let [{:keys [len]} header]
                  (st/bytes-fixed len)))))
      (st/wrap mask-st mask-st)))
