;;;; GNU Anubis -- an outgoing mail processor and the SMTP tunnel.
;;;; Copyright (C) 2003 The Anubis Team.
;;;;
;;;; GNU Anubis is free software; you can redistribute it and/or modify
;;;; it under the terms of the GNU General Public License as published by
;;;; the Free Software Foundation; either version 2 of the License, or
;;;; (at your option) any later version.
;;;;
;;;; GNU Anubis is distributed in the hope that it will be useful,
;;;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;;;; GNU General Public License for more details.
;;;;
;;;; You should have received a copy of the GNU General Public License
;;;; along with GNU Anubis; if not, write to the Free Software
;;;; Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
;;;;
;;;; GNU Anubis is released under the GPL with the additional exemption that
;;;; compiling, linking, and/or using OpenSSL is allowed.

(define debug-level 2)

(define (DEBUG level . rest)
  (if (>= debug-level level)
      (with-output-to-port
	  (current-error-port)
	(lambda ()
	  (display "DEBUG(")
	  (display level)
	  (display "):")
	  (for-each (lambda (x)
		      (display x))
		    rest)
	  (newline)))))

;;; A couple of auxiliary functions

(define (isspace? c)
  "Return #t if the character is a whitespace one"
  (case c
    ((#\space #\tab) #t)
    (else #f)))

(define (header->pair x)
  "Convert RFC822 header string into cons (HEADER-NAME . VALUE),
where HEADER-NAME is a Scheme internal symbol representing the header name
(all downcase) and VALUE is the string containing the header value"
  (let ((pos (string-index x #\:)))
    (if pos
	(cons
	 (string->symbol (string-downcase (substring x 0 pos)))
	 (let ((len (string-length x)))
	   (do ((i (1+ pos) (1+ i)))
	       ((or (= i len)
		    (not (isspace? (string-ref x i))))
		(substring x i)))))
	#f)))

(define (rewrite-subject subj)
  "Rewrite the subject line. If the value of the subject line begins
with \"ODP:\", replace it with \"Re:\". The original value of the subject
is preserved in X-Anubis-Preserved-Header header"
  (DEBUG 1 "rewrite-subject called with " subj)
  (let ((hdr (header->pair subj)))
    (cond
     ((eq? (car hdr) 'subject)
      (let ((val (header->pair (cdr hdr))))
	(cond
	 ((not val)
	  #t)
	 ((eq? (car val) 'odp)
	  (list
	   (string-append "Subject: Re: " (cdr val) "\n")
	   (string-append "X-Anubis-Preserved-Header: " (cdr hdr))))
	 (else #t))))
     (else #t))))

;;; This function illustrates the concept of Anubis postprocess
;;; functions.
;;; A postprocess function takes two arguments:
;;;
;;;   HDR   -- A list of message headers. Each list element is a cons
;;;            (NAME . VALUE), where NAME is the name of the header field,
;;;            and VALUE is its VALUE with final CRLF stripped off.
;;;   BODY  -- The message body.
;;;
;;; The function is expected to return cons:
;;;
;;;     (NEW-HDR . NEW-BODY)
;;;
;;; where
;;;   NEW-HDR is the new header list, or #t to indicate that the headers
;;;   are not changed.
;;;   NEW-BODY is a string representing the new body or a boolean with
;;;   the following meaning:
;;;     #f  --  delete entire body.
;;;     #t  --  preserve the body as is. 

(define (postprocess hdr body)
  "Encode the "Subject" header and the body using ROT-13. Add
X-Processed-By header."
  (DEBUG 1 "postprocess called with hdr=" hdr " and body=\"" body "\"")
  (cons (append
	 (map (lambda (x)
		(if (string-ci=? (car x) "subject")
		    (cons (car x) (rot-13 (cdr x)))
		    x))
	      hdr)
	 (list (cons "X-Processed-By" "GNU Anubis")))
	(rot-13 body)))

;; To test your output redirection:
(DEBUG 1 "LOADED anubis.scm")

