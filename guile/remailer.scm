;;;;
;;;; remailer.scm
;;;;
;;;; This file is part of GNU Anubis.
;;;; Copyright (C) 2003, 2004 The Anubis Team.
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

(define (get-opt-arg opt-args tag)
  (cond
   ((member tag opt-args) =>
    (lambda (x)
      (car (cdr x))))
   (else
    #f)))

(define (remailer-I hdr body . rest)
  "Reformat the body of the message so it can be used with type-I remailers.
Keyword arguments are:
	#:rrt address	--	Add Anon-To: header
	#:post address	--	Add Anon-Post-To: header
	#:latent time	--	Add Latent-Time: header
	#:random	--	Add random suffix to the latent time.
	#:header header	--	Add remailer header"
  (let* ((pfx (string-append
	      (cond
	       ((get-opt-arg rest #:rrt) =>
		(lambda (x)
		  (string-append "Anon-To: " x "\n")))
	       (else
		""))
	      (cond
	       ((get-opt-arg rest #:post) =>
		(lambda (x)
		  (string-append "Anon-Post-To: " x "\n")))
	       (else
		""))
	      (cond
	       ((get-opt-arg rest #:latent) =>
		(lambda (x)
		  (string-append "Latent-Time: +" x
				 (if (member #:random rest) "r" "") "\n")))
	       (else
		""))
	      (cond
	       ((get-opt-arg rest #:header) =>
		(lambda (x)
		  (string-append "##\n" x "\n")))
	       (else
		"")))))
    (if (string-null? pfx)
	(cons #t #t)
	(cons #t (string-append "::\n" pfx "\n" body)))))
	      
;;;; End of remailer.scm		
