(ns clj-net.inet.packet
  (:require [clj-lang-extra.core :refer [try-catch]]
            [clj-bytes.core :as b]
            [clj-bytes.struct :as st]))

(defmulti parse
  "Parse packet of type, return parsed packet
  and new context, or nil if parse failed."
  (fn [type _opts _context _buffer] type))

(defn ->raw-packet
  "Construct a raw packet."
  [buffer]
  {:type :raw :buffer buffer})

(defmethod parse :default [_type _opts context buffer]
  [(->raw-packet buffer) context])

(defn try-parse
  "Try to parse a packet with specified type,
  or a raw packet to ensure a non nil parse result."
  [type opts context buffer]
  (let [[parse-res ex] (try-catch #(parse type opts context buffer))]
    (if (and (nil? ex) (some? parse-res))
      parse-res
      [(->raw-packet buffer) context])))

(defn try-parse-next
  "Try to parse the next packet and assoc in current packet."
  ;; try to parse a packet with unknown type
  ([packet context buffer]
   (let [packet (cond-> packet
                  (not (b/empty? buffer))
                  (assoc :next-packet (->raw-packet buffer)))]
     [packet context]))
  ;; try to parse a packet with specified type
  ([packet type opts context buffer]
   (if-not (keyword? type)
     (try-parse-next packet context buffer)
     (let [packet (assoc packet :next-type type)]
       (if (b/empty? buffer)
         [packet context]
         (let [[next-packet context] (try-parse type opts context buffer)
               packet (assoc packet :next-packet next-packet)]
           [packet context])))))
  ;; try to parse a packet with specified length
  ([packet type opts context buffer length]
   (let [[packet buffer] (if (<= (b/count buffer) length)
                           [packet buffer]
                           (let [[buffer trail-buffer] (b/split-at! length buffer)
                                 packet (assoc packet :trail-buffer trail-buffer)]
                             [packet buffer]))]
     (if-not (= (b/count buffer) length)
       (try-parse-next packet context buffer)
       (try-parse-next packet type opts context buffer)))))

(defn parse-simple-packet
  ([st type opts context buffer]
   (parse-simple-packet st type opts context buffer nil))
  ([st type opts context buffer xf]
   (when-let [[st buffer] (-> buffer (st/unpack st))]
     (let [packet {:type type :st st}
           [packet context next-info] (when xf (xf packet context))
           {:keys [next-type next-length]} next-info]
       (if (nil? next-type)
         (-> packet (try-parse-next context buffer))
         (if (nil? next-length)
           (-> packet (try-parse-next next-type opts context buffer))
           (-> packet (try-parse-next next-type opts context buffer next-length))))))))
