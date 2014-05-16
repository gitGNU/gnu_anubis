;;;
;;; rot-13.scm
;;;
;;; This file is part of GNU Anubis.
;;; Copyright (C) 2003-2014 The Anubis Team.
;;;
;;; GNU Anubis is free software; you can redistribute it and/or modify it
;;; under the terms of the GNU General Public License as published by the
;;; Free Software Foundation; either version 3 of the License, or (at your
;;; option) any later version.
;;;
;;; GNU Anubis is distributed in the hope that it will be useful,
;;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;;; GNU General Public License for more details.
;;;
;;; You should have received a copy of the GNU General Public License along
;;; with GNU Anubis.  If not, see <http://www.gnu.org/licenses/>.

(define (rot-13-text input)
  "Encode the text using ROT-13 method"
  (let* ((text (string-append "" input))
	 (length (string-length text)))
    (do ((i 0 (1+ i)))
	((>= i length) text)
      (let ((c (string-ref text i)))
	(cond
	 ((char-lower-case? c)
	  (string-set! text i
		       (integer->char
			(+ 97 (modulo (+ (- (char->integer c) 97) 13) 26)))))
	 ((char-upper-case? c)
	  (string-set! text i
		       (integer->char
			(+ 65 (modulo (+ (- (char->integer c) 65) 13) 26))))))))))

(define (rot-13 hdr body . rest)
  (let ((rs (lambda (h)
	      (map (lambda (x)
		     (if (string-ci=? (car x) "subject")
			 (cons (car x) (rot-13-text (cdr x)))
			 x))
		   h))))
    (if (null? rest)
	(cons (rs hdr) (rot-13-text body))
	(cons (if (member #:subject rest)
		  (rs hdr)
		  #t)
	      (if (member #:body rest)
		  (rot-13-text body)
		  #t)))))
