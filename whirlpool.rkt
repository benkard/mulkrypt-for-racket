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
;;; This is an implementation of the WHIRLPOOL cryptographic hashing function.
;;;
;;; The implementation is directly based on the 2003 revised version of the
;;; original paper (“The WHIRLPOOL Hashing Function”) by Barreto and Rijmen.
;;; It is optimized for clarity, not performance.
;;;

(require "util.rkt")

(provide: [whirlpool (Bytes -> Exact-Nonnegative-Integer)])
(: whirlpool (Bytes -> Exact-Nonnegative-Integer))

(define-type Matrix Exact-Nonnegative-Integer)

(define rounds 10)

(define: (matrix-index [i : Byte] [j : Byte]) : Integer
  (- 512
     (+ (* 64 i) (* 8 j))
     8))

(define: (matrix-ref [m : Matrix]
                     [i : Byte]
                     [j : Byte])
  : Byte
  (bitwise-and (arithmetic-shift m (- (matrix-index i j)))
               #xff))

;; Unused.
(define: (matrix-set [m : Matrix]
                     [i : Byte]
                     [j : Byte]
                     [v : Byte])
  : Matrix
  (bitwise-ior (bitwise-and m
                            (bitwise-not
                             (arithmetic-shift #xff (matrix-index i j))))
               (arithmetic-shift v (matrix-index i j))))

(define-syntax first-2value
  (syntax-rules ()
    [(_ e) (let-values ([(x y) e]) x)]))

(define: (matrix-map [f : (Byte -> Byte)] [m : Matrix])
  : Matrix
  (make-matrix
   (λ (i j)
     (f (matrix-ref m i j)))))

(define: (make-matrix [proc : (Byte Byte -> Byte)]) : Matrix
  (for*/fold: ([m : Matrix 0])
              ([i : (U Positive-Fixnum Zero) (in-range 0 8)]
               [j : (U Positive-Fixnum Zero) (in-range 0 8)])
    (bitwise-ior (proc (assert i byte?) (assert j byte?))
                 (arithmetic-shift m 8))))

(define: (print-matrix [m : Matrix]) : Void
  (printf "~a" (format-matrix m)))

(define: (format-matrix [m : Matrix]) : String
  (with-output-to-string
   (λ ()
     (for ([i (in-range 0 8)])
       (printf "| ")
       (for ([j (in-range 0 8)])
         (let ([b (matrix-ref m (assert i byte?) (assert j byte?))])
           (if (> b #xf)
               (printf "~x " b)
               (printf " ~x " b))))
       (printf "|~%"))
     (printf "~%"))))


(define: (reverse-minibox [box : (Vectorof Byte)])
  : (Vectorof Byte)
  (let: ([antibox : (Vectorof Byte) (make-vector 16 0)])
    (for: ([i : (U Positive-Fixnum Zero) (in-range 0 16)])
      (vector-set! antibox (vector-ref box i) (assert i byte?)))
    (vector->immutable-vector antibox)))

(define: C-box : (Vector Byte Byte Byte Byte Byte Byte Byte Byte)
  #(#x1 #x1 #x4 #x1 #x8 #x5 #x2 #x9))
(define: S-box : (Vectorof Byte)
  #(#x18 #x23 #xc6 #xE8 #x87 #xB8 #x01 #x4F #x36 #xA6 #xd2 #xF5 #x79 #x6F #x91 #x52 #x60 #xBc #x9B #x8E #xA3 #x0c #x7B #x35 #x1d #xE0 #xd7 #xc2 #x2E #x4B #xFE #x57 #x15 #x77 #x37 #xE5 #x9F #xF0 #x4A #xdA #x58 #xc9 #x29 #x0A #xB1 #xA0 #x6B #x85 #xBd #x5d #x10 #xF4 #xcB #x3E #x05 #x67 #xE4 #x27 #x41 #x8B #xA7 #x7d #x95 #xd8 #xFB #xEE #x7c #x66 #xdd #x17 #x47 #x9E #xcA #x2d #xBF #x07 #xAd #x5A #x83 #x33 #x63 #x02 #xAA #x71 #xc8 #x19 #x49 #xd9 #xF2 #xE3 #x5B #x88 #x9A #x26 #x32 #xB0 #xE9 #x0F #xd5 #x80 #xBE #xcd #x34 #x48 #xFF #x7A #x90 #x5F #x20 #x68 #x1A #xAE #xB4 #x54 #x93 #x22 #x64 #xF1 #x73 #x12 #x40 #x08 #xc3 #xEc #xdB #xA1 #x8d #x3d #x97 #x00 #xcF #x2B #x76 #x82 #xd6 #x1B #xB5 #xAF #x6A #x50 #x45 #xF3 #x30 #xEF #x3F #x55 #xA2 #xEA #x65 #xBA #x2F #xc0 #xdE #x1c #xFd #x4d #x92 #x75 #x06 #x8A #xB2 #xE6 #x0E #x1F #x62 #xd4 #xA8 #x96 #xF9 #xc5 #x25 #x59 #x84 #x72 #x39 #x4c #x5E #x78 #x38 #x8c #xd1 #xA5 #xE2 #x61 #xB3 #x21 #x9c #x1E #x43 #xc7 #xFc #x04 #x51 #x99 #x6d #x0d #xFA #xdF #x7E #x24 #x3B #xAB #xcE #x11 #x8F #x4E #xB7 #xEB #x3c #x81 #x94 #xF7 #xB9 #x13 #x2c #xd3 #xE7 #x6E #xc4 #x03 #x56 #x44 #x7F #xA9 #x2A #xBB #xc1 #x53 #xdc #x0B #x9d #x6c #x31 #x74 #xF6 #x46 #xAc #x89 #x14 #xE1 #x16 #x3A #x69 #x09 #x70 #xB6 #xd0 #xEd #xcc #x42 #x98 #xA4 #x28 #x5c #xF8 #x86))
(define: E-box : (Vectorof Byte)
  #(#x1 #xB #x9 #xC #xD #x6 #xF #x3 #xE #x8 #x7 #x4 #xA #x2 #x5 #x0))
(define: R-box : (Vectorof Byte)
  #(#x7 #xC #xB #xD #xE #x4 #x9 #xF #x6 #x3 #x8 #xA #x2 #x5 #x1 #x0))
(define: E-antibox : (Vectorof Byte)
  (reverse-minibox E-box))
(define: R-antibox : (Vectorof Byte)
  (reverse-minibox R-box))
(define: (C-ref [i : Byte] [j : Byte]) : Byte
  (vector-ref C-box (modulo (+ j (- i)) 8)))
(define: C : Matrix
  (make-matrix (λ (i j) (C-ref i j))))


(define: (γ [m : Matrix]) : Matrix
  (matrix-map S m))

(define: (S [b : Byte]) : Byte
  (vector-ref S-box b))

(define: gf2^8+ : (Byte Byte -> Byte)
  bitwise-xor)

(define: (gf2^8* [a : Byte] [b : Byte]) : Byte
  ;; Multiplication in GF(2^8).
  ;;   http://en.wikipedia.org/wiki/Finite_field_arithmetic
  (let: loop : Byte ([a : Byte a]
                     [b : Byte b]
                     [p : Byte 0])
    (if (or (zero? a) (zero? b))
        p
        (let ([a-shift (bitwise-and (arithmetic-shift a 1) #xff)])
          (loop (if (bitwise-bit-set? a 7)
                    (bitwise-xor a-shift #b00011101)
                    a-shift)
                (assert (arithmetic-shift b -1) byte?)
                (if (bitwise-bit-set? b 0)
                    (bitwise-xor p a)
                    p))))))

(define: (θ [m : Matrix]) : Matrix
  (make-matrix
   (λ (i j)
     (for/fold: ([sum : Byte 0])
                ([k : (U Positive-Fixnum Zero) (in-range 0 8)])
       (let ([k (assert k byte?)])
         (gf2^8+ sum
                 (gf2^8* (matrix-ref m i k)
                         (matrix-ref C k j))))))))


(define: cr : (Vectorof Matrix)
  (vector->immutable-vector
   (ann
    (list->vector
     (ann (for/list: ([r : Integer (in-range 1 (add1 rounds))])
            (make-matrix
             (λ: ([i : Byte] [j : Byte])
               (if (zero? i)
                   (S (assert (+ (* 8 (sub1 r)) j)
                              byte?))
                   0))))
          (Listof Matrix)))
    (Vectorof Matrix))))

(define: σ : (Matrix -> Matrix -> Matrix)
  (curry bitwise-xor))

(define: (π [m : Matrix]) : Matrix
  (make-matrix
   (λ (i j)
     (matrix-ref m
                 (modulo (- i j) 8)
                 j))))

(define: (ρ [k : Matrix]) : (Matrix -> Matrix)
  (compose (σ k)
           (compose θ
                    (compose π
                             γ))))

(define: (K [m : Matrix] [r : Exact-Nonnegative-Integer]) : Matrix
  ((ρ (vector-ref cr (sub1 r))) m))

(define: (W [m : Matrix]) : (Matrix -> Matrix)
  ((inst compose Matrix Matrix Matrix)
   (let: loop : (Matrix -> Matrix)
                ([acc : (Matrix -> Matrix)        identity]
                 [Kr  : Matrix                    m]
                 [r   : Exact-Nonnegative-Integer 0])
     (if (>= r rounds)
         acc
         (let* ([next-r (add1 r)]
                [next-Kr (K Kr next-r)])
           (loop (compose (ρ next-Kr) acc)
                 next-Kr
                 next-r))))
   (σ m)))

(define: (bytes->matrix [b : Bytes]) : Matrix
  (for/fold: ([acc : Matrix 0])
             ([byte : Byte (in-bytes b)])
    (+ (arithmetic-shift acc 8) byte)))

(define: (length->bytes [n : Exact-Nonnegative-Integer]) : Bytes
  (let ([b (integer->bytes n 'big-endian)])
    (bytes-append (make-bytes (- 32 (bytes-length b)) 0) b)))

(define: (pad-whirlpool-bytes [b : Bytes]) : Bytes
  (let* ([missingno (modulo (- 32 (remainder (bytes-length b) 64))
                            64)]
         [padding   (cons #x80 (make-list (sub1 missingno) 0))]
         [len       (length->bytes (* 8 (bytes-length b)))])
    (bytes-append b (list->bytes padding) len)))

(define: (bytes->message [b : Bytes]) : (Listof Matrix)
  (let: ([pb : Bytes (pad-whirlpool-bytes b)])
    (reverse
     (for/fold: ([acc : (Listof Matrix) (list)])
                ([i : Exact-Nonnegative-Integer
                    (in-range 0 (quotient (bytes-length pb) 64))])
       (cons (bytes->matrix (subbytes pb (* i 64) (* (add1 i) 64)))
             acc)))))

(define: IV : Matrix
  0)

(define: (H [message : (Listof Matrix)]) : Matrix
  (for/fold: ([acc : Matrix IV])
             ([η   : Matrix (in-list message)])
    (bitwise-xor ((W acc) η)
                 acc
                 η)))

(define (whirlpool msg)
  (H (bytes->message msg)))

;; Should be:
;;   19FA61D75522A4669B44E39C1D2E1726C530232130D407F89AFEE0964997F7A7
;;   3E83BE698B288FEBCF88E3E03C4F0757EA8964E59B63D93708B138CC42A66EB3
;;(format "~X" (whirlpool #"")))
;;(print-matrix (whirlpool #"")))
