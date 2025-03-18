(ns clj-net.abnf
  (:require [clojure.string :as str]
            [clojure.set :as set]))

;;; lexer

(def define-stmt-re #"^[0-9a-zA-Z-<>]* *=")

(defn read-rule-str [lines]
  (loop [rule-lines [(first lines)] lines (rest lines)]
    (let [line (first lines)]
      (if (or (nil? line) (re-find define-stmt-re line))
        [(str/join \newline rule-lines) lines]
        (recur (conj rule-lines line) (rest lines))))))

(defn read-rule-strs [lines]
  (lazy-seq
   (when (seq lines)
     (let [[rule lines] (read-rule-str lines)]
       (cons rule (read-rule-strs lines))))))

(defn rule-strs-seq [s]
  (->> (str/split-lines s)
       (map str/trim)
       (remove empty?)
       (drop-while #(str/starts-with? % ";"))
       read-rule-strs))

(comment
  (-> ";; begin

       rulelist       =  1*( rule / (*c-wsp c-nl) )

       rule           =  rulename defined-as elements c-nl
                              ; continues if next line starts
                              ;  with white space

       rulename       =  ALPHA *(ALPHA / DIGIT / \"-\")

       ;; end"
      rule-strs-seq))

(defmulti read-token
  (fn [s] (first s)))

(defn read-tokens [s]
  (lazy-seq
   (when (seq s)
     (let [[token s] (read-token s)]
       (cons token (read-tokens s))))))

(defn tokens-seq [s]
  (->> s read-tokens (remove #{:comment :ws})))

(def nl-chars
  #{\return \newline})

(def ws-chars
  #{\return \newline \space \tab \formfeed})

(def digit-chars
  #{\0 \1 \2 \3 \4 \5 \6 \7 \8 \9})

(def lower-alpha-chars
  #{\a \b \c \d \e \f \g \h \i \j \k \l \m \n \o \p \q \r \s \t \u \v \w \x \y \z})

(def upper-alpha-chars
  #{\A \B \C \D \E \F \G \H \I \J \K \L \M \N \O \P \Q \R \S \T \U \V \W \X \Y \Z})

(def alpha-chars
  (set/union lower-alpha-chars upper-alpha-chars))

(def id-chars
  (set/union alpha-chars digit-chars #{\-}))

(defn read-literal [charset s]
  (loop [cs [] s s]
    (let [c (first s)]
      (if-not (contains? charset c)
        [(str/join cs) s]
        (recur (conj cs c) (rest s))))))

(defn skip-comment [s]
  {:pre [(= (first s) \;)]}
  (loop [s (rest s)]
    (if (or (empty? s) (contains? nl-chars (first s)))
      s
      (recur (rest s)))))

(defmethod read-token \; [s]
  [:comment (skip-comment s)])

(defn skip-ws-chars [s]
  (if-not (contains? ws-chars (first s))
    s
    (recur (rest s))))

(doseq [c ws-chars]
  (defmethod read-token c [s] [:ws (skip-ws-chars s)]))

^:rct/test
(comment
  (-> (read-token "  hello world  ") (update 1 str/join)) ; => [:ws "hello world  "]
  )

(defn read-id-literal [s]
  {:pre [(contains? alpha-chars (first s))]}
  (read-literal id-chars s))

(defn read-id-token [s]
  (let [[id s] (read-id-literal s)
        id (str/lower-case id)]
    [{:type :id :id id} s]))

(doseq [c alpha-chars]
  (defmethod read-token c [s] (read-id-token s)))

(defmethod read-token \< [s]
  (let [[id s] (read-id-token (rest s))]
    (if (= (first s) \>)
      [id (rest s)]
      (throw (ex-info "invalid id token: unclosed <" {:reason :lexer/id})))))

^:rct/test
(comment
  (-> (read-token "hello world") (update 1 str/join)) ; => [{:type :id :id "hello"} " world"]
  (-> (read-token "<hello>world") (update 1 str/join)) ; => [{:type :id :id "hello"} "world"]
  )

(defmethod read-token \= [s] [{:type :define} (rest s)])

(defn read-str-literal [s]
  {:pre [(= (first s) \")]}
  (loop [cs [] s (rest s)]
    (let [c (first s)]
      (if (some? c)
        (if (= c \")
          [(str/join cs) (rest s)]
          (recur (conj cs c) (rest s)))
        (throw (ex-info "invalid str token: unclosed \"" {:reason :lexer/str}))))))

(defn read-str-token [s case-sensitive?]
  (let [[str s] (read-str-literal s)
        str (cond-> str
              (not case-sensitive?) str/lower-case)]
    [{:type :str :case-sensitive? case-sensitive? :str str} s]))

(defmethod read-token \" [s]
  (read-str-token s false))

^:rct/test
(comment
  (-> (read-token "\"hello\"world") (update 1 str/join)) ; => [{:type :str :case-sensitive? false :str "hello"} "world"]
  )

(defmulti read-escape-token
  (fn [s] (first s)))

(defmethod read-token \% [s]
  (read-escape-token (rest s)))

(defmethod read-escape-token \s [s]
  (read-str-token (rest s) true))

(defmethod read-escape-token \i [s]
  (read-str-token (rest s) false))

^:rct/test
(comment
  (-> (read-token "%s\"hello\"world") (update 1 str/join)) ; => [{:type :str :case-sensitive? true :str "hello"} "world"]
  (-> (read-token "%i\"hello\"world") (update 1 str/join)) ; => [{:type :str :case-sensitive? false :str "hello"} "world"]
  )

(def char-literal-chars
  (set/union id-chars #{\.}))

(defn read-char-literal [s]
  (read-literal char-literal-chars s))

(defn str->int [s base char-map]
  {:pre [(every? #(contains? char-map %) s)]}
  (->> s
       (reduce
        (fn [i c]
          (+ (* base i) (get char-map c)))
        0)))

(defn str->ascii-int [s base char-map]
  {:post [(<= 0 % 255)]}
  (str->int s base char-map))

(defn char-literal->token [s base char-map]
  (let [sp (str/split s #"-" 2)]
    (if (= (count sp) 2)
      (let [[start end] (->> sp (map #(str->ascii-int % base char-map)))
            chars (->> (range start (inc end)) (map char) set)]
        {:type :chars :chars chars})
      (let [str (->> (str/split s #"\.")
                     (map #(str->int % base char-map))
                     (map char)
                     str/join)]
        {:type :str :case-sensitive? true :str str}))))

(defn read-char-token [s base char-map]
  (let [[char-literal s] (read-char-literal s)]
    [(char-literal->token char-literal base char-map) s]))

(def char-map-2
  {\0 0 \1 1})

(def char-map-10
  {\0 0 \1 1 \2 2 \3 3 \4 4 \5 5 \6 6 \7 7 \8 8 \9 9})

(def char-map-16
  {\0 0 \1 1 \2 2 \3 3 \4 4 \5 5 \6 6 \7 7 \8 8 \9 9
   \a 10 \b 11 \c 12 \d 13 \e 14 \f 15
   \A 10 \B 11 \C 12 \D 13 \E 14 \F 15})

(defmethod read-escape-token \b [s]
  (read-char-token (rest s) 2 char-map-2))

(defmethod read-escape-token \d [s]
  (read-char-token (rest s) 10 char-map-10))

(defmethod read-escape-token \x [s]
  (read-char-token (rest s) 16 char-map-16))

^:rct/test
(comment
  (-> (read-token "%d13.10 hello") (update 1 str/join)) ; => [{:type :str :case-sensitive? false :str "\r\n"} " hello"]
  (-> (read-token "%x30-39 hello") (update 1 str/join)) ; => [{:type :chars :chars #{\0 \1 \2 \3 \4 \5 \6 \7 \8 \9}} " hello"]
  )

(def repeat-literal-chars
  (set/union digit-chars #{\*}))

(defn read-repeat-literal [s]
  (read-literal repeat-literal-chars s))

(defn repeat-literal->token [s]
  (let [sp (str/split s #"\*" 2)
        [min max] (if (= (count sp) 2)
                    (let [[min max] sp
                          min (when-not (str/blank? min) (str->int min 10 char-map-10))
                          max (when-not (str/blank? max) (str->int max 10 char-map-10))]
                      [min max])
                    (let [n (str->int s 10 char-map-10)]
                      [n n]))]
    (cond-> {:type :repeat}
      (some? min) (assoc :min min)
      (some? max) (assoc :max max))))

(defn read-repeat-token [s]
  (let [[repeat-literal s] (read-repeat-literal s)]
    [(repeat-literal->token repeat-literal) s]))

(doseq [c repeat-literal-chars]
  (defmethod read-token c [s] (read-repeat-token s)))

^:rct/test
(comment
  (-> (read-token "*hello world") (update 1 str/join)) ; => [{:type :repeat} "hello world"]
  (-> (read-token "3hello world") (update 1 str/join)) ; => [{:type :repeat :min 3 :max 3} "hello world"]
  (-> (read-token "1*3hello world") (update 1 str/join)) ; => [{:type :repeat :min 1 :max 3} "hello world"]
  )

(defmethod read-token \/ [s] [{:type :alt} (rest s)])
(defmethod read-token \( [s] [{:type :group-open} (rest s)])
(defmethod read-token \) [s] [{:type :group-close} (rest s)])
(defmethod read-token \[ [s] [{:type :opt-open} (rest s)])
(defmethod read-token \] [s] [{:type :opt-close} (rest s)])

(comment
  (-> "rulelist       =  1*( rule / (*c-wsp c-nl) )" tokens-seq)
  (-> "rule           =  rulename defined-as elements c-nl" tokens-seq)
  (-> "rulename       =  ALPHA *(ALPHA / DIGIT / \"-\")" tokens-seq)
  (-> "defined-as     =  *c-wsp (\"=\" / \"=/\") *c-wsp" tokens-seq))

;;; parser

(declare read-alt-expr)

(defmulti read-expr
  (fn [tokens] (-> tokens first :type)))

(defmethod read-expr :default [_tokens])

(defmethod read-expr :id [tokens]
  [(first tokens) (rest tokens)])

(defmethod read-expr :str [tokens]
  [(first tokens) (rest tokens)])

(defmethod read-expr :chars [tokens]
  [(first tokens) (rest tokens)])

(defmethod read-expr :repeat [tokens]
  (let [token (first tokens)
        [expr tokens] (read-expr (rest tokens))]
    [(assoc token :expr expr) tokens]))

(defmethod read-expr :group-open [tokens]
  (let [[expr tokens] (read-alt-expr (rest tokens))]
    (if (= :group-close (-> tokens first :type))
      [expr (rest tokens)]
      (throw (ex-info "invalid group token: unclosed group" {:reason :parser/group})))))

(defmethod read-expr :opt-open [tokens]
  (let [[expr tokens] (read-alt-expr (rest tokens))]
    (if (= :opt-close (-> tokens first :type))
      [{:type :opt :expr expr} (rest tokens)]
      (throw (ex-info "invalid opt token: unclosed opt" {:reason :parser/opt})))))

(defn read-cat-expr [tokens]
  (loop [exprs [] tokens tokens]
    (if-let [[expr tokens] (read-expr tokens)]
      (recur (conj exprs expr) tokens)
      (let [expr (if (= (count exprs) 1)
                   (first exprs)
                   {:type :cat :exprs exprs})]
        [expr tokens]))))

(defn read-alt-expr [tokens]
  (let [[expr tokens] (read-cat-expr tokens)]
    (loop [exprs [expr] tokens tokens]
      (if (= :alt (-> tokens first :type))
        (let [[expr tokens] (read-cat-expr (rest tokens))]
          (recur (conj exprs expr) tokens))
        (let [expr (if (= (count exprs) 1)
                     (first exprs)
                     {:type :alt :exprs exprs})]
          [expr tokens])))))

(defn read-define-stmt [tokens]
  (let [[[id define] tokens] (split-at 2 tokens)]
    (if (and (= :id (:type id)) (= :define (:type define)))
      (let [[inc-alt? tokens] (if-not (= :alt (-> tokens first :type))
                                [false tokens]
                                [true (rest tokens)])
            [expr tokens] (read-alt-expr tokens)]
        (if (empty? tokens)
          {:id (:id id) :inc-alt? inc-alt? :expr expr}
          (throw (ex-info "invalid define stmt: unknown tokens" {:reason :parser/define}))))
      (throw (ex-info "invalid define stmt: invalid define token" {:reason :parser/define})))))

(comment
  (-> "rulelist       =  1*( rule / (*c-wsp c-nl) )" tokens-seq read-define-stmt)
  (-> "rule           =  rulename defined-as elements c-nl" tokens-seq read-define-stmt)
  (-> "rulename       =  ALPHA *(ALPHA / DIGIT / \"-\")" tokens-seq read-define-stmt)
  (-> "defined-as     =  *c-wsp (\"=\" / \"=/\") *c-wsp" tokens-seq read-define-stmt))

(defn parse-rule-str [s]
  (->> s tokens-seq read-define-stmt))

(defn parse-rules-text [s]
  (->> s rule-strs-seq (map parse-rule-str)))

(comment
  (-> "rulelist       =  1*( rule / (*c-wsp c-nl) )

       rule           =  rulename defined-as elements c-nl
                              ; continues if next line starts
                              ;  with white space

       rulename       =  ALPHA *(ALPHA / DIGIT / \"-\")"
      parse-rules-text))

;;; compile

(defn reduce-rules
  ([rules]
   (reduce-rules {} rules))
  ([base rules]
   (->> rules
        (reduce
         (fn [m {:keys [id inc-alt? expr]}]
           (if-not inc-alt?
             (assoc m id expr)
             (let [orig-expr (get m id)]
               (if (some? orig-expr)
                 (assoc m id {:type :alt :exprs [orig-expr expr]})
                 (throw (ex-info "invalid inc alt define: unknown id" {:reason :compile/reduce :id id}))))))
         base))))

(def core-rules-text "
ALPHA          =  %x41-5A / %x61-7A   ; A-Z / a-z

BIT            =  \"0\" / \"1\"

CHAR           =  %x01-7F
                       ; any 7-bit US-ASCII character,
                       ;  excluding NUL

CR             =  %x0D
                       ; carriage return

CRLF           =  CR LF
                       ; Internet standard newline

CTL            =  %x00-1F / %x7F
                       ; controls

DIGIT          =  %x30-39
                       ; 0-9

DQUOTE         =  %x22
                       ; \" (Double Quote)

HEXDIG         =  DIGIT / \"A\" / \"B\" / \"C\" / \"D\" / \"E\" / \"F\"

HTAB           =  %x09
                       ; horizontal tab

LF             =  %x0A
                       ; linefeed

LWSP           =  *(WSP / CRLF WSP)
                       ; Use of this linear-white-space rule
                       ;  permits lines containing only white
                       ;  space that are no longer legal in
                       ;  mail headers and have caused
                       ;  interoperability problems in other
                       ;  contexts.
                       ; Do not use when defining mail
                       ;  headers and use with caution in
                       ;  other contexts.

OCTET          =  %x00-FF
                       ; 8 bits of data

SP             =  %x20

VCHAR          =  %x21-7E
                       ; visible (printing) characters

WSP            =  SP / HTAB
                       ; white space
")

(def core-rules
  (->> core-rules-text parse-rules-text reduce-rules))

(defn compile-rules-text
  ([s]
   (compile-rules-text core-rules s))
  ([base s]
   (->> s parse-rules-text (reduce-rules base))))

;;; match

(defmulti match-expr
  (fn [_rules expr _s] (:type expr)))

(defmethod match-expr :id [rules expr s]
  (let [{:keys [id]} expr
        sub-expr (get rules id)]
    (if (some? sub-expr)
      (when-let [[match s] (match-expr rules sub-expr s)]
        (let [{:keys [str]} match]
          [{:str str :expr expr :sub-matches [match]} s]))
      (throw (ex-info "invalid id expr: unknown id" {:reason :match/id :id id})))))

(defmethod match-expr :str [_rules expr s]
  (let [{:keys [case-sensitive? str]} expr
        cnt (count str)
        [cs s] (split-at cnt s)
        match-str (str/join cs)]
    (when (= (cond-> match-str (not case-sensitive?) str/lower-case) str)
      [{:str match-str :expr expr} s])))

(defmethod match-expr :chars [_rules expr s]
  (let [{:keys [chars]} expr
        c (first s)]
    (when (contains? chars c)
      [{:str (str c) :expr expr} (rest s)])))

(defmethod match-expr :repeat [rules expr s]
  (let [{:keys [min max] sub-expr :expr} expr]
    (loop [matches [] s s]
      (if-let [[match s] (when (not (and (some? max) (>= (count matches) max)))
                           (when-let [[match s] (match-expr rules sub-expr s)]
                             (when (or (pos? (count (:str match)))
                                       (< (count matches) (or min 0)))
                               [match s])))]
        (recur (conj matches match) s)
        (when (>= (count matches) (or min 0))
          (let [str (->> matches (map :str) str/join)]
            [{:str str :expr expr :sub-matches matches} s]))))))

(defmethod match-expr :group [rules expr s]
  (let [{sub-expr :expr} expr]
    (when-let [[match s] (match-expr rules sub-expr s)]
      (let [{:keys [str]} match]
        [{:str str :expr expr :sub-matches [match]} s]))))

(defmethod match-expr :opt [rules expr s]
  (let [{sub-expr :expr} expr]
    (if-let [[match s] (match-expr rules sub-expr s)]
      (let [{:keys [str]} match]
        [{:str str :expr expr :sub-matches [match]} s])
      [{:str "" :expr expr :sub-matches []} s])))

(defmethod match-expr :cat [rules expr s]
  (let [{sub-exprs :exprs} expr]
    (loop [matches [] sub-exprs sub-exprs s s]
      (if (empty? sub-exprs)
        (let [str (->> matches (map :str) str/join)]
          [{:str str :expr expr :sub-matches matches} s])
        (when-let [[match s] (match-expr rules (first sub-exprs) s)]
          (recur (conj matches match) (rest sub-exprs) s))))))

(defmethod match-expr :alt [rules expr s]
  (let [{sub-exprs :exprs} expr]
    (->> sub-exprs
         (some
          (fn [sub-expr]
            (when-let [[match s] (match-expr rules sub-expr s)]
              (let [{:keys [str]} match]
                [{:str str :expr expr :sub-matches [match]} s])))))))

(defmethod match-expr :ref [_rules expr s]
  (let [{:keys [id rules]} expr
        sub-expr (get rules id)]
    (if (some? sub-expr)
      (when-let [[match s] (match-expr rules sub-expr s)]
        (let [{:keys [str]} match]
          [{:str str :expr expr :sub-matches [match]} s]))
      (throw (ex-info "invalid ref expr: unknown id" {:reason :match/ref :id id})))))

(defn refer-to
  ([m id rules]
   (refer-to m id rules id))
  ([m id rules as]
   (assoc m (str/lower-case as) {:type :ref :id (str/lower-case id) :rules rules})))

(defn match [rules rule-id s]
  (let [expr {:type :id :id (str/lower-case rule-id)}]
    (when-let [[match s] (match-expr rules expr s)]
      (when (empty? s)
        match))))

(defn simplify-match
  ([match]
   (simplify-match match nil))
  ([match {:keys [min-match-str-cnt] :or {min-match-str-cnt 4}}]
   (letfn [(f [{:keys [str expr sub-matches]}]
             (let [id (when (= (:type expr) :id) (:id expr))]
               (cond-> {:str str}
                 (some? id) (assoc :id id)
                 (>= (count str) min-match-str-cnt) (assoc :sub-matches (->> sub-matches (remove (comp empty? :str)) (mapv f))))))]
     (f match))))
