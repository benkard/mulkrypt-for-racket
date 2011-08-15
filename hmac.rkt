#lang typed/racket
;;; Copyright 2011, Matthias Andreas Benkard.
;;;
;;;-----------------------------------------------------------------------------
;;; This program is free software: you can redistribute it and/or modify
;;; it under the terms of the GNU Affero General Public License as published by
;;; the Free Software Foundation, either version 3 of the License, or
;;; (at your option) any later version.
;;;
;;; This program is distributed in the hope that it will be useful,
;;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;;; GNU Affero General Public License for more details.
;;;
;;; You should have received a copy of the GNU Affero General Public License
;;; along with this program.  If not, see <http://www.gnu.org/licenses/>.
;;;-----------------------------------------------------------------------------
;;;

(require "util.rkt")

(provide: [hmac ((Bytes -> Exact-Nonnegative-Integer)
                 Exact-Nonnegative-Integer
                 Exact-Nonnegative-Integer
                 Bytes
                 Bytes
                 ->
                 Exact-Nonnegative-Integer)])

;; Example:
;;
;;  (hmac whirlpool 64 64 #"<secret key>" #"hello")
;;
(define (hmac hashfn blocksize hashsize key msg)
  (let ([opad (make-bytes blocksize #x5c)]
        [ipad (make-bytes blocksize #x36)]
        [padded-key
         (pad-bytes (if (> (bytes-length key) blocksize)
                        (integer->bytes (hashfn key))
                        key)
                    blocksize
                    #x0
                    'left)])
    (hashfn (bytes-append (integer->bytes/size
                           (bitwise-xor (bytes->integer opad)
                                        (bytes->integer padded-key))
                           blocksize)
                          (integer->bytes/size
                           (hashfn
                            (bytes-append
                             (integer->bytes/size
                              (bitwise-xor (bytes->integer ipad)
                                           (bytes->integer padded-key))
                              blocksize)
                             msg))
                           hashsize)))))

;; According to Ironclad:
;;
;; CRYPTO[12]> (map nil
;;                  (lambda (x) (format t "~x" x))
;;                  (hmac-digest (make-hmac #() 'whirlpool)))
;; 57D73990319055DEFA7739FF7B72406A927BBC54E8FCDC98E145FA4C36CE83
;; A9CF165AD1E0D1925F93AC1D12B985A26044E9FB1B9CCE24301FAA76EAAB53
;;
#;
(begin
  (require "whirlpool.rkt")
  (printf "~x~%" (hmac whirlpool 64 64 #"" #"")))
