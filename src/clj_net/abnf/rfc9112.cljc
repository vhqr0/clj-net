(ns clj-net.abnf.rfc9112
  (:require [clj-net.abnf :as abnf]
            [clj-net.abnf.rfc3986 :as rfc3986]
            [clj-net.abnf.rfc9110 :as rfc9110]))

(def rules-text "
HTTP-message = start-line CRLF *( field-line CRLF ) CRLF [ message-body ]
HTTP-name = %x48.54.54.50 ; HTTP
HTTP-version = HTTP-name \"/\" DIGIT \".\" DIGIT

;; bws = <BWS, see [HTTP], Section 5.6.3>

;; OWS = <OWS, see [HTTP], Section 5.6.3>

;; RWS = <RWS, see [HTTP], Section 5.6.3>

Transfer-Encoding = [ transfer-coding *( OWS \",\" OWS transfer-coding ) ]

;; absolute-URI = <absolute-URI, see [URI], Section 4.3>
absolute-form = absolute-URI
;; absolute-path = <absolute-path, see [HTTP], Section 4.1>
asterisk-form = \"*\"
;; authority = <authority, see [URI], Section 3.2>
authority-form = uri-host \":\" port

chunk = chunk-size [ chunk-ext ] CRLF chunk-data CRLF
chunk-data = 1*OCTET
chunk-ext = *( BWS \";\" BWS chunk-ext-name [ BWS \"=\" BWS chunk-ext-val ] )
chunk-ext-name = token
chunk-ext-val = token / quoted-string
chunk-size = 1*HEXDIG
chunked-body = *chunk last-chunk trailer-section CRLF

field-line = field-name \":\" OWS field-value OWS
;; field-name = <field-name, see [HTTP], Section 5.1>
;; field-value = <field-value, see [HTTP], Section 5.5>

last-chunk = 1*\"0\" [ chunk-ext ] CRLF

message-body = *OCTET
method = token

obs-fold = OWS CRLF RWS
;; obs-text = <obs-text, see [HTTP], Section 5.6.4>
origin-form = absolute-path [ \"?\" query ]

;; port = <port, see [URI], Section 3.2.3>

;; query = <query, see [URI], Section 3.4>
;; quoted-string = <quoted-string, see [HTTP], Section 5.6.4>

reason-phrase = 1*( HTAB / SP / VCHAR / obs-text )
request-line = method SP request-target SP HTTP-version
request-target = origin-form / absolute-form / authority-form /
 asterisk-form

start-line = request-line / status-line
status-code = 3DIGIT
status-line = HTTP-version SP status-code SP [ reason-phrase ]

;; token = <token, see [HTTP], Section 5.6.2>
trailer-section = *( field-line CRLF )
;; transfer-coding = <transfer-coding, see [HTTP], Section 10.1.4>

;; uri-host = <host, see [URI], Section 3.2.2>
")

(def refs
  {"bws" {:type :ref :id "bws" :rules rfc9110/rules}
   "ows" {:type :ref :id "ows" :rules rfc9110/rules}
   "rws" {:type :ref :id "rws" :rules rfc9110/rules}
   "absolute-uri" {:type :ref :id "absolute-uri" :rules rfc3986/rules}
   "absolute-path" {:type :ref :id "absolute-path" :rules rfc9110/rules}
   "authority" {:type :ref :id "authority" :rules rfc3986/rules}
   "field-name" {:type :ref :id "field-name" :rules rfc9110/rules}
   "field-value" {:type :ref :id "field-value" :rules rfc9110/rules}
   "obs-text" {:type :ref :id "obs-text" :rules rfc9110/rules}
   "port" {:type :ref :id "port" :rules rfc3986/rules}
   "query" {:type :ref :id "query" :rules rfc3986/rules}
   "quoted-string" {:type :ref :id "quoted-string" :rules rfc9110/rules}
   "token" {:type :ref :id "token" :rules rfc9110/rules}
   "transfer-coding" {:type :ref :id "transfer-coding" :rules rfc9110/rules}
   "uri-host" {:type :ref :id "host" :rules rfc3986/rules}})

(def rules
  (abnf/compile-rules-text (merge abnf/core-rules refs) rules-text))

(comment
  (-> (abnf/match rules "http-message" "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n") abnf/simplify-match))
