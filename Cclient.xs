/*
 *	Cclient.xs
 *
 *	Copyright (c) 1998,1999,2000,2001 Malcolm Beattie
 *
 *	You may distribute under the terms of either the GNU General Public
 *	License or the Artistic License, as specified in the README file.
 */

/*
 * Must include mail.h before perl's stuff since mail.h uses op
 * and we can't simply undef it because we need it too for GIMME.
 * mail.h also defines INIT and OP_PROTOTYPE so we have to undefine
 * them afterwards since perl needs to define them too. Still worse:
 * we actually need the cclient INIT macro so we copy its definition
 * from mail.h and call it CCLIENT_LOCAL_INIT instead. This macro
 * therefore needs keeping in sync with mail.h.
 * For imap-2000 we also need to include stddef.h first to ensure
 * size_t is defined since misc.h needs it.
 */

#include <stddef.h>
#include "mail.h"
#include "osdep.h"
#include "rfc822.h"
#include "misc.h"
#include "smtp.h"
#include "utf8.h"
#include "criteria.h"

#define CCLIENT_LOCAL_INIT(s,d,data,size) \
	((*((s)->dtb = &d)->init) (s,data,size))
#undef INIT

#ifdef OP_PROTOTYPE
#undef OP_PROTOTYPE
#endif

#ifndef strcaseEQ
#define strcaseEQ(s1,s2) (!strcasecmp(s1,s2))
#endif

/* Ensure na and sv_undef get defined */
#define PERL_POLLUTE

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

typedef MAILSTREAM *Mail__Cclient;
typedef SENDSTREAM *Mail__Cclient__SMTP;

/* Magic signature for Cclient's mg_private is "Cc" */
#define Mail__Cclient_MAGIC_SIGNATURE 0x4363

#define MAX_LEN_ARRAY	14
#define MUST_EXIST	1
#define DATE_BUFF_SIZE	64

static HV *mailstream2sv;	/* Map MAILSTREAM* to SV* */
static HV *stash_Cclient;	/* Mail::Cclient:: stash */
static HV *stash_Address;	/* Mail::Cclient::Address stash */
static HV *stash_Envelope;	/* Mail::Cclient::Envelope stash */
static HV *stash_Body;		/* Mail::Cclient::Body stash */
static HV *stash_Elt;		/* Mail::Cclient::Elt stash */
static HV *callback;		/* Maps callback names to Perl SV callbacks */
static SV *address_fields;	/* \%Mail::Cclient::Address::FIELDS */
static SV *envelope_fields;	/* \%Mail::Cclient::Envelope::FIELDS */
static SV *body_fields;		/* \%Mail::Cclient::Body::FIELDS */
static SV *elt_fields;		/* \%Mail::Cclient::Elt::FIELDS */

#include "patchlevel.h"
#if PATCHLEVEL < 4
static SV *newRV_noinc(SV *ref) {
	SV *sv = newRV(ref);
	SvREFCNT_dec(ref);
	return sv;
}
#endif

static SV *str_to_sv(char *str) {
	return str ? newSVpv(str, 0) : newSVsv(&sv_undef);
}

static HV *av_to_hv(AV *av, int n) {
	SV **keysp = av_fetch(av, n, FALSE);
	if(keysp) {
		SV *sv = *keysp;
		if(SvGMAGICAL(sv)) mg_get(sv);
		if(SvROK(sv)) {
			sv = SvRV(sv); 
			if(SvTYPE(sv) == SVt_PVHV) return (HV*)sv;
		}
	}
	croak("Can't coerce array into hash");
	return Nullhv;
}

static SV *get_mailstream_sv(MAILSTREAM *stream, char *class) {
	SV **svp = hv_fetch(mailstream2sv, (char*)&stream, sizeof(stream), FALSE);
	SV *sv;

#ifdef PERL_CCLIENT_DEBUG
	fprintf(stderr, "get_mailstream_sv(%p, %s), hv_fetch returns SV %p\n",
		stream, class, svp ? *svp : 0); /* debug */
#endif
	if(svp)
		sv = *svp;
	else {
		SV *rv = (SV*)newHV();
		sv = sv_bless(newRV(rv), stash_Cclient);
		SvREFCNT_dec(rv);
		sv_magic(rv, newSViv((IV)stream), '~', 0, 0);
		SvMAGIC(rv)->mg_private = Mail__Cclient_MAGIC_SIGNATURE;
		hv_store(mailstream2sv, (char*)&stream, sizeof(stream), sv, 0);
	}
#ifdef PERL_CCLIENT_DEBUG
	fprintf(stderr, "returning %p, type %d\n", sv, SvTYPE(sv)); /* debug */
#endif
	return sv;
}

static SV *mm_callback(char *name) {
	dSP;
	SV **svp = hv_fetch(callback, name, strlen(name), FALSE);

#ifdef PERL_CCLIENT_DEBUG
	fprintf(stderr, "mm_callback(%s)\n", name);
#endif
	if(svp && SvOK(*svp))
		return *svp;
	return 0;
}

/*
 * SMTP
 */

char *generate_message_id() {
	static short osec = 0, cnt = 0;
	char *id;
	time_t now;
	struct tm *now_x;
	char *host;

	now = time((time_t *)0);
	now_x = localtime(&now);
	id = (char *)fs_get(128 * sizeof(char));	
	if(now_x->tm_sec == osec)
		cnt++;
	else {
		cnt = 0;
		osec = now_x->tm_sec;
	}
	host = getenv("HOSTNAME") ;
	if(!host) host = "localhost" ;

	sprintf(id,"<Mail::Cclient.%.4s.%.20s.%02d%02d%02d%02d%02d%02d%X.%d@%.50s>",
		VERSION, OSNAME, (now_x->tm_year) % 100, now_x->tm_mon + 1,
		now_x->tm_mday, now_x->tm_hour, now_x->tm_min, now_x->tm_sec,
		cnt, getpid(), host);

	return(id);
}

static void make_mail_envelope(ENVELOPE *env, char *dhost, HV* hv) {
	if(hv_exists(hv, "from", 4)) {
		SV **value = hv_fetch(hv, "from", 4, 0);
		rfc822_parse_adrlist(&env->from, SvPV(*value, na), dhost);
		env->return_path = rfc822_cpy_adr(env->from);
	}
	if(hv_exists(hv, "to", 2)) {
		SV **value = hv_fetch(hv, "to", 2, 0);
		rfc822_parse_adrlist(&env->to, SvPV(*value, na), dhost);
	}
	if(hv_exists(hv, "cc", 2)) {
		SV **value = hv_fetch(hv, "cc", 2, 0);
		rfc822_parse_adrlist(&env->cc, SvPV(*value, na), dhost);
	}
	if(hv_exists(hv, "bcc", 3)) {
		SV **value = hv_fetch(hv, "bcc", 3, 0);
		rfc822_parse_adrlist(&env->bcc, SvPV(*value, na), dhost);
	}
	if(hv_exists(hv, "sender", 6)) {
		SV **value = hv_fetch(hv, "sender", 6, 0);
		rfc822_parse_adrlist(&env->sender, SvPV(*value, na), dhost);
	}
	if(hv_exists(hv, "reply_to", 8)) {
		SV **value = hv_fetch(hv, "reply_to", 8, 0);
		rfc822_parse_adrlist(&env->reply_to, SvPV(*value, na), dhost);
	}
	if(hv_exists(hv, "return_path", 11)) {
		SV **value = hv_fetch(hv, "return_path", 11, 0);
		rfc822_parse_adrlist(&env->return_path, SvPV(*value, na), dhost);
	}
	if(hv_exists(hv, "in_reply_to", 11)) {
		SV **value = hv_fetch(hv, "in_reply_to", 11, 0);
		env->in_reply_to = SvPV(*value, na);
	}
	if(hv_exists(hv, "message_id", 10)) {
		SV **value = hv_fetch(hv, "message_id", 10, 0);
		env->message_id = SvPV(*value, na);
	} else
		env->message_id = generate_message_id();

	if(hv_exists(hv, "subject", 7)) {
		SV **value = hv_fetch(hv, "subject", 7, 0);
		env->subject = SvPV(*value, na);
	}
	if(hv_exists(hv, "remail", 6)) {
		SV **value = hv_fetch(hv, "remail", 6, 0);
		env->remail = SvPV(*value, na);
	}
	if(hv_exists(hv, "date", 4)) {
		SV **value = hv_fetch(hv, "date", 4, 0);
		env->date = SvPV(*value, na);
	} else {
		char buf[DATE_BUFF_SIZE];
		rfc822_date(buf);
		env->date = cpystr(buf);
	}
	if(hv_exists(hv, "newsgroups", 10)) {
		SV **value = hv_fetch(hv, "newsgroups", 10, 0);
		env->newsgroups = SvPV(*value, na);
	}
	if(hv_exists(hv, "followup_to", 11)) {
		SV **value = hv_fetch(hv, "followup_to", 11, 0);
		env->followup_to = SvPV(*value, na);
	}
	if(hv_exists(hv, "references", 10)) {
		SV **value = hv_fetch(hv, "references", 11, 0);
		env->references = SvPV(*value, na);
	}
}

static PARAMETER *make_mail_parameter(SV *sv) {
	PARAMETER *param = NULL, *p = NULL;

	if(SvROK(sv) && SvTYPE(SvRV(sv))) {
		AV *av = (AV*)SvRV(sv);
		I32 k;
		for(k = 0; k < av_len(av) + 1; k++) {
			HV *hv = av_to_hv(av, k);

			if(p) p = p->next = mail_newbody_parameter();
			else param = p = mail_newbody_parameter();

			if(hv_exists(hv, "attribute", 9)) {
				SV **value = hv_fetch(hv, "attribute", 9, 0);
				p->attribute = SvPV(*value, na);
			}
			if(hv_exists(hv, "value", 5)) {
				SV **value = hv_fetch(hv, "value", 5, 0);
				p->value = SvPV(*value, na);
			}
		}
	}
	return(param);
}

int set_encoding(char *enc) {
	return(strcaseEQ(enc, "7bit")
		? ENC7BIT
		: strcaseEQ(enc, "8bit")
			? ENC8BIT
			: strcaseEQ(enc, "binary")
				? ENCBINARY
				: strcaseEQ(enc, "base64")
					? ENCBASE64
					: strcaseEQ(enc, "quoted-printable")
						? ENCQUOTEDPRINTABLE
						: ENCOTHER);
}

int set_type(char *type) {
	return(strcaseEQ(type, "text")
		? TYPETEXT
		: strcaseEQ(type, "multipart")
			? TYPEMULTIPART
			: strcaseEQ(type, "message")
				? TYPEMESSAGE
				: strcaseEQ(type, "application")
					? TYPEAPPLICATION
					: strcaseEQ(type, "audio")
						? TYPEAUDIO
						: strcaseEQ(type, "image")
							? TYPEIMAGE
							: strcaseEQ(type, "video")
								? TYPEVIDEO
								: strcaseEQ(type, "model")
									? TYPEMODEL
									: TYPEOTHER);
}

static void make_mail_disposition(SV *sv, BODY **body) {
	HV *hv = (HV*)SvRV(sv);
	if(hv_exists(hv, "type", 4)) {
		SV **v = hv_fetch(hv, "type", 4, 0);
		(*body)->disposition.type = SvPV(*v, na);
	}
	if(hv_exists(hv, "parameter", 9)) {
		SV **v = hv_fetch(hv, "parameter", 9, 0);
		(*body)->disposition.parameter = make_mail_parameter(*v);
	}
}

static void addfile(char *filename, SIZEDTEXT *st) {
	PerlIO *fp;
	unsigned char *data;
	struct stat statbuf;
	int bytesread;

	if ((fp = PerlIO_open(filename, "rb")) == NULL) {
		croak("Failed to open file \"%s\"", filename);
		return;
	}
	PerlLIO_fstat(PerlIO_fileno(fp), &statbuf);
	data = (char*)fs_get(statbuf.st_size);
	if(!(bytesread = PerlIO_read(fp, data, statbuf.st_size))) {
		return;
	}
	PerlIO_close(fp);

	st->data = (char*)fs_get(statbuf.st_size);
	memcpy(st->data, data, statbuf.st_size + 1);
	st->size = statbuf.st_size;
	free(data);
}

static void set_mime_type(BODY **body) {
	if((*body)->type == TYPEOTHER){
		if((*body)->contents.text.data[0] == 'G' &&
			(*body)->contents.text.data[1] == 'I' &&
				(*body)->contents.text.data[2] == 'F') {
			(*body)->type = TYPEIMAGE;
			(*body)->subtype = cpystr("GIF");
		} else if(((*body)->contents.text.size > 9) &&
			(*body)->contents.text.data[0] == 0xFF &&
				(*body)->contents.text.data[1] == 0xD8 &&
					(*body)->contents.text.data[2] == 0xFF &&
						(*body)->contents.text.data[3] == 0xE0 &&
							!strncmp((char *)&(*body)->contents.text.data[6], "JFIF", 4)) {
			(*body)->type = TYPEIMAGE;
			(*body)->subtype = cpystr("JPEG");
		} else if(((*body)->contents.text.size > 3) &&
			(*body)->contents.text.data[0] == 0x89 &&
				(*body)->contents.text.data[1] == 'P' &&
					(*body)->contents.text.data[2] == 'N' &&
						(*body)->contents.text.data[3] == 'G') {
			(*body)->type = TYPEIMAGE;
			(*body)->subtype = cpystr("PNG");
		} else if(((*body)->contents.text.data[0] == 'M' &&
			(*body)->contents.text.data[1] == 'M') ||
				((*body)->contents.text.data[0] == 'I' &&
					(*body)->contents.text.data[1] == 'I')) {
			(*body)->type = TYPEIMAGE;
			(*body)->subtype = cpystr("TIFF");
		} else if(((*body)->contents.text.data[0] == '%' &&
			(*body)->contents.text.data[1] == '!') ||
				((*body)->contents.text.data[0] == '\004' &&
					(*body)->contents.text.data[1] == '%' &&
						(*body)->contents.text.data[2] == '!')) {
			(*body)->type = TYPEAPPLICATION;
			(*body)->subtype = cpystr("PostScript");
		} else if((*body)->contents.text.data[0] == '%' &&
				!strncmp((char*)(*body)->contents.text.data+1, "PDF-", 4)) {
			(*body)->type = TYPEAPPLICATION;
			(*body)->subtype = cpystr("PDF");
		} else if((*body)->contents.text.data[0] == '.' &&
				!strncmp((char*)(*body)->contents.text.data+1, "snd", 3)) {
			(*body)->type = TYPEAUDIO;
			(*body)->subtype = cpystr("Basic");
		} else if(((*body)->contents.text.size > 3) &&
			(*body)->contents.text.data[0] == 0x00 &&
				(*body)->contents.text.data[1] == 0x05 &&
					(*body)->contents.text.data[2] == 0x16 &&
						(*body)->contents.text.data[3] == 0x00) {
			(*body)->type = TYPEAPPLICATION;
			(*body)->subtype = cpystr("APPLEFILE");
		} else if(((*body)->contents.text.size > 3) &&
			(*body)->contents.text.data[0] == 0x50 &&
				(*body)->contents.text.data[1] == 0x4b &&
					(*body)->contents.text.data[2] == 0x03 &&
						(*body)->contents.text.data[3] == 0x04) {
			(*body)->type = TYPEAPPLICATION;
			(*body)->subtype = cpystr("ZIP");
		}
		/*
		 * if type was set above, but no encoding specified, go
		 * ahead and make it BASE64...
		 */
		if((*body)->type != TYPEOTHER && (*body)->encoding == ENCOTHER)
			(*body)->encoding = ENCBINARY;
	}
}

static void make_mail_body(BODY *body, HV* hv) {
	if(hv_exists(hv, "content_type", 12)) {
		char *type = NULL, *subtype = NULL;
		SV **value = hv_fetch(hv, "content_type", 12, 0);
		char *ctype = SvPV(*value, na);

		type = strtok(ctype, "/");
		if(type) {
			body->type = set_type(type);
			subtype = strtok(NULL, "/");
			if(subtype) body->subtype = subtype;
		}
	} else body->type = TYPEOTHER;

	if(hv_exists(hv, "encoding", 8)) {
		SV **value = hv_fetch(hv, "encoding", 8, 0);
		body->encoding = set_encoding(SvPV(*value, na));
	}
	if(hv_exists(hv, "disposition", 11)) {
		SV **value = hv_fetch(hv, "disposition", 11, 0);
		make_mail_disposition(*value, &body);
	}
	if(hv_exists(hv, "parameter", 9)) {
		SV **value = hv_fetch(hv, "parameter", 9, 0);
		body->parameter = make_mail_parameter(*value);
	}
	if(hv_exists(hv, "description", 11)) {
		SV **value = hv_fetch(hv, "description", 11, 0);
		body->description = SvPV(*value, na);
	}
	if(hv_exists(hv, "id", 2)) {
		SV **value = hv_fetch(hv, "id", 2, 0);
		body->id = SvPV(*value, na);
	}
	if(hv_exists(hv, "md5", 3)) {
		SV **value = hv_fetch(hv, "md5", 3, 0);
		body->md5 = SvPV(*value, na);
	}
	if(hv_exists(hv, "path", 4)) {
		SV **value = hv_fetch(hv, "path", 4, 0);
		unsigned char *data;
		addfile(SvPV(*value, na), &body->contents.text);
		if(body->type == TYPEOTHER)
			set_mime_type(&body);
	} else if(hv_exists(hv, "data", 4)) {
		SV **value = hv_fetch(hv, "data", 4, 0);
		STRLEN len;
		body->contents.text.data = SvPV(*value, len);
		body->contents.text.size = len;
		body->size.bytes = (int)(len/8);
	}
	if(hv_exists(hv, "part", 4)) {
		SV **value = hv_fetch(hv, "part", 4, 0);
		PART **part = &body->nested.part;
		AV *av = (AV*)SvRV(*value);
		I32 len = av_len(av) + 1;
		I32 k;
		if(!body->type || body->type != TYPEMULTIPART)
			body->type = TYPEMULTIPART;
		for(k = 0; k < len; k++) {
			HV *hv = av_to_hv(av, k);
			*part = mail_newbody_part();
			make_mail_body(&(*part)->body, hv);
			part = &(*part)->next;
		}
	}
}

long transfer(void *f, char *buf) {
	PerlIO_write(f, buf, strlen(buf));
	return(1L);
}

static void save_rfc822_tmp(ENVELOPE *env, BODY *body, PerlIO *fp) {
	char tmp[8*MAILTMPLEN];
	rfc822_output(tmp, env, body, transfer, fp, 1);
}

/*
 * C-client data structure manipulation
 */

/*
 * make_address turns a C-client ADDRESS (representing a list of
 * email addresses) into a Perl ref to a list of addresses. Each
 * single address is represented by Perl as a list ref
 *     [keyref, personal, adl, mailbox, host, error]
 * (though the error entry is optional and may be absent)
 * blessed into class Mail::Cclient::Address. keyref is a ref to
 * %Mail::Cclient::Address::FIELDS for 5.005 pseudo-hash access to the
 * object. Note that make_address returns an AV*, not a ref to one.
 */
static AV *
make_address(ADDRESS *address) {
	AV *alist = newAV();
	for (; address; address = address->next) {
		AV *a = newAV();
		av_push(a, SvREFCNT_inc(address_fields));
		av_push(a, str_to_sv(address->personal));
		av_push(a, str_to_sv(address->adl));
		av_push(a, str_to_sv(address->mailbox));
		av_push(a, str_to_sv(address->host));
		if(address->error)
			av_push(a, str_to_sv(address->error));
		av_push(alist, sv_bless(newRV_noinc((SV*)a), stash_Address));
	}
	return alist;
}

/*
 * make_envelope turns a C-client ENVELOPE (representing the
 * RFC822 headers of a message) into a Perl list ref of the form
 *     [keyref, remail, return_path, date, from, sender, reply_to,
 *      subject, to, cc, bcc, in_reply_to, message_id,
 *      newsgroups, followup_to, references]
 * blessed into Mail::Cclient::Envelope. keyref is a ref to
 * %Mail::Cclient::Envelope::FIELDS for 5.005 pseudo-hash access
 * to the object.
 */
static SV *
make_envelope(ENVELOPE *envelope) {
	AV *e = newAV();
	av_push(e, SvREFCNT_inc(envelope_fields));
	av_push(e, str_to_sv(envelope->remail));
	av_push(e, newRV_noinc((SV*)make_address(envelope->return_path)));
	av_push(e, str_to_sv(envelope->date));
	av_push(e, newRV_noinc((SV*)make_address(envelope->from)));
	av_push(e, newRV_noinc((SV*)make_address(envelope->sender)));
	av_push(e, newRV_noinc((SV*)make_address(envelope->reply_to)));
	av_push(e, str_to_sv(envelope->subject));
	av_push(e, newRV_noinc((SV*)make_address(envelope->to)));
	av_push(e, newRV_noinc((SV*)make_address(envelope->cc)));
	av_push(e, newRV_noinc((SV*)make_address(envelope->bcc)));
	av_push(e, str_to_sv(envelope->in_reply_to));
	av_push(e, str_to_sv(envelope->message_id));
	av_push(e, str_to_sv(envelope->newsgroups));
	av_push(e, str_to_sv(envelope->followup_to));
	av_push(e, str_to_sv(envelope->references));
	return sv_bless(newRV_noinc((SV*)e), stash_Envelope);
}

/*
 * make_elt turns a C-client MESSAGECACHE ("elt") into a Perl list
 * ref of the form
 *     [keyref, msgno, date, flags, rfc822_size]
 * blessed into Mail::Cclient::Elt. Date contains the internal date
 * information which held in separate bit fields in the underlying
 * C structure but which is presented in Perl as a string in the form
 *     yyyy-mm-dd hh:mm:ss [+-]hhmm
 * The flags field is a ref to a list of strings such as
 * \Deleted, \Flagged, \Answered etc (as per RFC 2060) plus
 * user-defined flag names set via the Mail::Cclient setflag method.
 * %Mail::Cclient::Envelope::FIELDS for 5.005 pseudo-hash access
 * to the object. keyref is a ref to %Mail::Cclient::Elt::FIELDS for
 * 5.005 pseudo-hash access to the object.
 */
static SV *
make_elt(MAILSTREAM *stream, MESSAGECACHE *elt) {
	AV *av = newAV();
	AV *flags = newAV();
	char datebuf[26]; /* to fit "yyyy-mm-dd hh:mm:ss [+-]hhmm\0" */
	int i;
    
	av_push(av, SvREFCNT_inc(elt_fields));
	av_push(av, newSViv(elt->msgno));
	/*
	 * year field is OK until 2098 since it's an offset from BASEYEAR
	 * which in newer cclients is 1970 (was 1969) and elt->year is a
	 * bitfield with 7 bits.
	*/
	sprintf(datebuf, "%04d-%02d-%02d %02d:%02d:%02d %c%02d%02d",
		BASEYEAR + elt->year, elt->month, elt->day, elt->hours,
		elt->minutes, elt->seconds,
		elt->zoccident ? '-' : '+', elt->zhours, elt->zminutes);
	av_push(av, newSVpv(datebuf, sizeof(datebuf)));
	if(elt->seen)
		av_push(flags, newSVpv("\\Seen", 5));
	if(elt->deleted)
		av_push(flags, newSVpv("\\Deleted", 8));
	if(elt->flagged)
		av_push(flags, newSVpv("\\Flagged", 8));
	if(elt->answered)
		av_push(flags, newSVpv("\\Answered", 9));
	if(elt->draft)
		av_push(flags, newSVpv("\\Draft", 6));
	if(elt->valid)
		av_push(flags, newSVpv("\\Valid", 6));
	if(elt->recent)
		av_push(flags, newSVpv("\\Recent", 7));
	if(elt->searched)
		av_push(flags, newSVpv("\\Searched", 9));

	for(i = 0; i < NUSERFLAGS; i++) {
		if(elt->user_flags & (1 << i)) {
			char *fl = stream->user_flags[i];
			SV *sv = fl ? newSVpv(fl, 0) : newSVpvf("user_flag_%d", i);
			av_push(flags, sv);
		}
	}
	av_push(av, newRV_noinc((SV*)flags));
	av_push(av, newSViv(elt->rfc822_size)); 
	return sv_bless(newRV_noinc((SV*)av), stash_Elt);
}

/*
 * make_thread
 */
static AV *
make_thread(THREADNODE *thr) {
	AV *av = newAV();
	THREADNODE *t;
	while(thr) {
		if(thr->num) {
			av_push(av, newSViv(thr->num));
			if(t = thr->next) {
				while (t) {
					if(t->branch) {
						av_push(av, newRV_noinc((SV*)make_thread(t)));
						t = NIL;
					} else {
						av_push(av, newSViv(t->num));
						t = t->next;
					}
				}
			}
		} else {
			av_push(av, newRV_noinc((SV*)make_thread(thr->next)));
		}
		thr = thr->branch;
	}
	return av;
}

/*          
 * make_sort
 */
static AV *
make_sort(unsigned long *slst) {
	AV *av = newAV();
	unsigned long *sl;
	for(sl = slst; *sl; sl++) {
		av_push(av, newSViv(*sl));
	}
	return av;
}

static AV *
stringlist_to_av(STRINGLIST *s) {
	AV *av = newAV();
	for (; s; s = s->next)
		av_push(av, newSVpv(s->text.data, s->text.size));
	return av;
}

static STRINGLIST *av_to_stringlist(AV *av) {
	STRINGLIST *rets = 0;
	STRINGLIST **s = &rets;
	SV **svp = AvARRAY(av);
	I32 count;
	for (count = AvFILL(av); count >= 0; count--) {
		STRLEN len;
		*s =  mail_newstringlist();
		(*s)->text.data = cpystr(SvPV(*svp, len));
		(*s)->text.size = len;
		s = &(*s)->next;
		svp++;
	}
	return rets;
}

static AV *
push_parameter(AV *av, PARAMETER *param) {
	for(; param; param = param->next) {
		av_push(av, newSVpv(param->attribute, 0));
		av_push(av, newSVpv(param->value, 0));
	}
	return av;
}

static SV *
make_body(BODY *body) {
	AV *av = newAV();
	SV *nest;
	AV *paramav = newAV();

	av_push(av, SvREFCNT_inc(body_fields));
	av_push(av, newSVpv(body_types[body->type], 0));
	av_push(av, newSVpv(body_encodings[body->encoding], 0));
	av_push(av, str_to_sv(body->subtype));
	av_push(av, newRV_noinc((SV*)push_parameter(newAV(), body->parameter)));
	av_push(av, str_to_sv(body->id));
	av_push(av, str_to_sv(body->description));
	if (body->type == TYPEMULTIPART) {
		AV *parts = newAV();
		PART *p;
		for (p = body->nested.part; p; p = p->next)
			av_push(parts, make_body(&p->body));
		nest = newRV_noinc((SV*)parts);
	} else if (body->type == TYPEMESSAGE && strEQ(body->subtype, "RFC822")) {
		AV *mess = newAV();
		MESSAGE *msg = body->nested.msg;
		av_push(mess, msg ? make_envelope(msg->env) : &sv_undef);
		av_push(mess, msg ? make_body(msg->body) : &sv_undef);
		nest = newRV_noinc((SV*)mess);
	} else
		nest = newSVsv(&sv_undef);

	av_push(av, nest);
	av_push(av, newSViv(body->size.lines));
	av_push(av, newSViv(body->size.bytes));
	av_push(av, str_to_sv(body->md5));
	av_push(paramav, str_to_sv(body->disposition.type));
	paramav = push_parameter(paramav, body->disposition.parameter);
	av_push(av, newRV_noinc((SV*)paramav));
	return sv_bless(newRV_noinc((SV*)av), stash_Body);
}

/*
 * Interfaces to C-client callbacks
 */

void mm_searched(MAILSTREAM *stream, unsigned long number)
{
    dSP;
    SV *sv = mm_callback("searched");
    if (!sv)
	return;
    PUSHMARK(sp);
    XPUSHs(sv_mortalcopy(get_mailstream_sv(stream, 0)));
    XPUSHs(sv_2mortal(newSViv(number)));
    PUTBACK;
    perl_call_sv(sv, G_DISCARD);
}

void mm_exists(MAILSTREAM *stream, unsigned long number)
{
    dSP;
    SV *sv = mm_callback("exists");
    if (!sv)
	return;
    PUSHMARK(sp);
    XPUSHs(sv_mortalcopy(get_mailstream_sv(stream, 0)));
    XPUSHs(sv_2mortal(newSViv(number)));
    PUTBACK;
    perl_call_sv(sv, G_DISCARD);
}

void mm_expunged(MAILSTREAM *stream, unsigned long number)
{
    dSP;
    SV *sv = mm_callback("expunged");
    if (!sv)
	return;
    PUSHMARK(sp);
    XPUSHs(sv_mortalcopy(get_mailstream_sv(stream, 0)));
    XPUSHs(sv_2mortal(newSViv(number)));
    PUTBACK;
    perl_call_sv(sv, G_DISCARD);
}

void mm_flags(MAILSTREAM *stream, unsigned long number)
{
    dSP;
    SV *sv = mm_callback("flags");
    if (!sv)
	return;
    PUSHMARK(sp);
    XPUSHs(sv_mortalcopy(get_mailstream_sv(stream, 0)));
    XPUSHs(sv_2mortal(newSViv(number)));
    PUTBACK;
    perl_call_sv(sv, G_DISCARD);
}

void mm_notify(MAILSTREAM *stream, char *string, long errflg)
{
    dSP;
    SV *sv = mm_callback("notify");
    if (!sv)
	return;
    PUSHMARK(sp);
    XPUSHs(sv_mortalcopy(get_mailstream_sv(stream, 0)));
    XPUSHs(sv_2mortal(newSVpv(string, 0)));
    XPUSHs(sv_2mortal(newSViv(errflg)));
    PUTBACK;
    perl_call_sv(sv, G_DISCARD);
}

void mm_list(MAILSTREAM *stream, int delimiter, char *mailbox, long attributes)
{
    dSP;
    char delimchar;
    SV *sv = mm_callback("list");
    if (!sv)
	return;
    delimchar = (char)delimiter;
    PUSHMARK(sp);
    XPUSHs(sv_mortalcopy(get_mailstream_sv(stream, 0)));
    XPUSHs(sv_2mortal(newSVpv(&delimchar, 1)));
    XPUSHs(sv_2mortal(newSVpv(mailbox, 0)));
    if (attributes & LATT_NOINFERIORS)
	XPUSHs(sv_2mortal(newSVpv("noinferiors", 0)));
    if (attributes & LATT_NOSELECT)
	XPUSHs(sv_2mortal(newSVpv("noselect", 0)));
    if (attributes & LATT_MARKED)
	XPUSHs(sv_2mortal(newSVpv("marked", 0)));
    if (attributes & LATT_UNMARKED)
	XPUSHs(sv_2mortal(newSVpv("unmarked", 0)));
    PUTBACK;
    perl_call_sv(sv, G_DISCARD);
}

void mm_lsub(MAILSTREAM *stream, int delimiter, char *mailbox, long attributes)
{
    dSP;
    SV *sv = mm_callback("lsub");
    if (!sv)
	return;
    PUSHMARK(sp);
    XPUSHs(sv_mortalcopy(get_mailstream_sv(stream, 0)));
    XPUSHs(sv_2mortal(newSViv(delimiter)));
    XPUSHs(sv_2mortal(newSVpv(mailbox, 0)));
    XPUSHs(sv_2mortal(newSViv(attributes)));
    PUTBACK;
    perl_call_sv(sv, G_DISCARD);
}

void mm_status(MAILSTREAM *stream, char *mailbox, MAILSTATUS *status)
{
    dSP;
    SV *sv = mm_callback("status");
    if (!sv)
	return;
    PUSHMARK(sp);
    XPUSHs(sv_mortalcopy(get_mailstream_sv(stream, 0)));
    XPUSHs(sv_2mortal(newSVpv(mailbox, 0)));
    if (status->flags & SA_MESSAGES) {
	XPUSHs(sv_2mortal(newSVpv("messages", 0)));
	XPUSHs(sv_2mortal(newSViv(status->messages)));
    }
    if (status->flags & SA_RECENT) {
	XPUSHs(sv_2mortal(newSVpv("recent", 0)));
	XPUSHs(sv_2mortal(newSViv(status->recent)));
    }
    if (status->flags & SA_UNSEEN) {
	XPUSHs(sv_2mortal(newSVpv("unseen", 0)));
	XPUSHs(sv_2mortal(newSViv(status->unseen)));
    }
    if (status->flags & SA_UIDVALIDITY) {
	XPUSHs(sv_2mortal(newSVpv("uidvalidity", 0)));
	XPUSHs(sv_2mortal(newSViv(status->uidvalidity)));
    }
    if (status->flags & SA_UIDNEXT) {
	XPUSHs(sv_2mortal(newSVpv("uidnext", 0)));
	XPUSHs(sv_2mortal(newSViv(status->uidnext)));
    }
    PUTBACK;
    perl_call_sv(sv, G_DISCARD);
}

void mm_log(char *string, long errflg)
{
    dSP;
    SV *sv = mm_callback("log");
    if (!sv)
	return;
    PUSHMARK(sp);
    XPUSHs(sv_2mortal(newSVpv(string, 0)));
    XPUSHs(sv_2mortal(newSVpv((
	errflg == NIL ? "info" :
	errflg == PARSE ? "parse" :
	errflg == WARN ? "warn" :
	errflg == ERROR ? "error" : "unknown"), 0)));
    PUTBACK;
    perl_call_sv(sv, G_DISCARD);
}

void mm_dlog(char *string)
{
    dSP;
    SV *sv = mm_callback("dlog");
    if (!sv)
	return;
    PUSHMARK(sp);
    XPUSHs(sv_2mortal(newSVpv(string, 0)));
    PUTBACK;
    perl_call_sv(sv, G_DISCARD);
}

void mm_fatal (char *string)
{
    dSP;
    SV *sv = mm_callback("fatal");
    if (!sv)
	return;
    PUSHMARK(sp);
    XPUSHs(sv_2mortal(newSVpv(string, 0)));
    PUTBACK;
    perl_call_sv(sv, G_DISCARD);
}

void mm_login(NETMBX *mb, char *user, char *password, long trial)
{
    dSP;
    SV *sv = mm_callback("login");
    HV *hv;
    SV *retsv;
    STRLEN len;
    char *str;
    I32 items;

    if (!sv)
	croak("mandatory login callback not set");
    ENTER;
    SAVETMPS;
    PUSHMARK(sp);
    hv = newHV();
    hv_store(hv, "host", 4, str_to_sv(mb->host), 0);
    hv_store(hv, "user", 4, str_to_sv(mb->user), 0);
    hv_store(hv, "mailbox", 7, str_to_sv(mb->mailbox), 0);
    hv_store(hv, "service", 7, str_to_sv(mb->service), 0);
    hv_store(hv, "port", 4, newSViv(mb->port), 0);
    if(mb->anoflag)
	hv_store(hv, "anoflag", 7, newSViv(1), 0);
    if(mb->dbgflag)
	hv_store(hv, "dbgflag", 7, newSViv(1), 0);
    if(mb->secflag)
	hv_store(hv, "secflag", 7, newSViv(1), 0);
    if(mb->sslflag)
	hv_store(hv, "sslflag", 7, newSViv(1), 0);
    if(mb->trysslflag)
	hv_store(hv, "trysslflag", 10, newSViv(1), 0);
    if(mb->novalidate)
	hv_store(hv, "novalidate", 10, newSViv(1), 0);
    XPUSHs(sv_2mortal(newRV((SV*)hv)));
    SvREFCNT_dec((SV*)hv);
    XPUSHs(sv_2mortal(newSViv(trial)));
    PUTBACK;
    items = perl_call_sv(sv, G_ARRAY);
    SPAGAIN;
    if (items != 2)
	croak("login callback failed to return (user, password)");
    retsv = POPs;	/* password */
    str = SvPV(retsv, len);
    /*
     * By brief inspection (but it's not documented), c-client seems
     * to pass a buffer of size MAILTMPLEN for the user and password
     * strings so we make sure we don't copy in more than that.
     * We don't use strcnpy all the time since it pads its destination
     * with \0 characters and there may be parts of c-client that
     * don't actually pass in that large a buffer.
     */
    if (len >= MAILTMPLEN)
	strncpy(password, str, MAILTMPLEN - 1);
    else
	strcpy(password, str);
    retsv = POPs;	/* user */
    str = SvPV(retsv, len);
    if (len >= MAILTMPLEN)
	strncpy(user, str, MAILTMPLEN - 1);
    else
	strcpy(user, str);
    
    PUTBACK;
    FREETMPS;
    LEAVE;
}

void mm_critical(MAILSTREAM *stream)
{
    dSP;
    SV *sv = mm_callback("critical");
    if (!sv)
	return;
    PUSHMARK(sp);
    XPUSHs(sv_mortalcopy(get_mailstream_sv(stream, 0)));
    PUTBACK;
    perl_call_sv(sv, G_DISCARD);
}

void mm_nocritical(MAILSTREAM *stream)
{
    dSP;
    SV *sv = mm_callback("nocritical");
    if (!sv)
	return;
    PUSHMARK(sp);
    XPUSHs(sv_mortalcopy(get_mailstream_sv(stream, 0)));
    PUTBACK;
    perl_call_sv(sv, G_DISCARD);
}

long mm_diskerror(MAILSTREAM *stream, long errcode, long serious)
{
    dSP;
    SV *sv = mm_callback("diskerror");
    if (!sv)
	return;
    PUSHMARK(sp);
    XPUSHs(sv_mortalcopy(get_mailstream_sv(stream, 0)));
    XPUSHs(sv_2mortal(newSViv(errcode)));
    XPUSHs(sv_2mortal(newSViv(serious)));
    PUTBACK;
    perl_call_sv(sv, G_DISCARD);
}

MODULE = Mail::Cclient	PACKAGE = Mail::Cclient	PREFIX = mail_

PROTOTYPES: DISABLE

Mail::Cclient
mail_open(stream, mailbox, ...)
		Mail::Cclient	stream
		char *		mailbox
	PREINIT:
		int i;
		long options = 0;
	CODE:
		for (i = 2; i < items; i++) {
			char *option = SvPV(ST(i), na);
			if(strEQ(option, "debug"))
				options |= OP_DEBUG;
			else if(strEQ(option, "readonly"))
				options |= OP_READONLY;
			else if(strEQ(option, "anonymous"))
				options |= OP_ANONYMOUS;
			else if(strEQ(option, "shortcache"))
				options |= OP_SHORTCACHE;
			else if(strEQ(option, "silent"))
				options |= OP_SILENT;
			else if(strEQ(option, "prototype"))
				options |= OP_PROTOTYPE;
			else if(strEQ(option, "halfopen"))
				options |= OP_HALFOPEN;
			else if(strEQ(option, "expunge"))
				options |= OP_EXPUNGE;
			else if(strEQ(option, "secure"))
				options |= OP_SECURE;
			else if(strEQ(option, "tryssl"))
				options |= OP_TRYSSL;
			else if(strEQ(option, "mulnewsrc"))
				options |= OP_MULNEWSRC;
			else {
				croak("unknown option \"%s\" passed to Mail::Cclient::open",
					option);
			}
		}
		if(stream)
			hv_delete(mailstream2sv, (char*)stream, sizeof(stream), G_DISCARD);
	RETVAL = mail_open(stream, mailbox, options);
		if(!RETVAL)
			XSRETURN_UNDEF;
	OUTPUT:
		RETVAL
	CLEANUP:
#ifdef PERL_CCLIENT_DEBUG
	fprintf(stderr, "storing stream %p\n", RETVAL); /*debug*/
#endif
	hv_store(mailstream2sv, (char*)&RETVAL, sizeof(RETVAL),
		SvREFCNT_inc(ST(0)), 0);

void
mail_close(stream, ...)
		Mail::Cclient	stream
	CODE:
		hv_delete(mailstream2sv, (char*)stream, sizeof(stream), G_DISCARD);
		if(items == 1)
			mail_close(stream);
		else {
			long options = 0;
			int i;
			for(i = 1; i < items; i++) {
				char *option = SvPV(ST(i), na);
				if(strEQ(option, "expunge"))
					options |= CL_EXPUNGE;
				else {
					croak("unknown option \"%s\" passed to"
							" Mail::Cclient::close", option);
				}
		}
		mail_close_full(stream, options);
	}


void
mail_list(stream, ref, pat)
	Mail::Cclient	stream
	char *		ref
	char *		pat

void
mail_scan(stream, ref, pat, contents)
	Mail::Cclient	stream
	char *		ref
	char *		pat
	char *		contents

void
mail_lsub(stream, ref, pat)
	Mail::Cclient	stream
	char *		ref
	char *		pat

unsigned long
mail_subscribe(stream, mailbox)
	Mail::Cclient	stream
	char *		mailbox

unsigned long
mail_unsubscribe(stream, mailbox)
	Mail::Cclient	stream
	char *		mailbox

unsigned long
mail_create(stream, mailbox)
	Mail::Cclient	stream
	char *		mailbox

unsigned long
mail_delete(stream, mailbox)
	Mail::Cclient	stream
	char *		mailbox

unsigned long
mail_rename(stream, oldname, newname)
	Mail::Cclient	stream
	char *		oldname
	char *		newname

long
mail_status(stream, mailbox, ...)
	Mail::Cclient	stream
	char *		mailbox
    PREINIT:
	int i;
	long flags = 0;
    CODE:
	for (i = 2; i < items; i++) {
	    char *flag = SvPV(ST(i), na);
	    if (strEQ(flag, "messages"))
		flags |= SA_MESSAGES;
	    else if (strEQ(flag, "recent"))
		flags |= SA_RECENT;
	    else if (strEQ(flag, "unseen"))
		flags |= SA_UNSEEN;
	    else if (strEQ(flag, "uidnext"))
		flags |= SA_UIDNEXT;
	    else if (strEQ(flag, "uidvalidity"))
		flags |= SA_UIDVALIDITY;
	    else {
		croak("unknown flag \"%s\" passed to Mail::Cclient::status",
		      flag);
	    }
	}
	RETVAL = mail_status(stream, mailbox, flags);
    OUTPUT:
	RETVAL


MODULE = Mail::Cclient	PACKAGE = Mail::Cclient	PREFIX = mailstream_

#define mailstream_mailbox(stream) stream->mailbox
#define mailstream_use(stream) stream->use
#define mailstream_sequence(stream) stream->sequence
#define mailstream_rdonly(stream) stream->rdonly
#define mailstream_anonymous(stream) stream->anonymous
#define mailstream_halfopen(stream) stream->halfopen
#define mailstream_secure(stream) stream->secure
#define mailstream_tryssl(stream) stream->tryssl
#define mailstream_mulnewsrc(stream) stream->mulnewsrc
#define mailstream_perm_seen(stream) stream->perm_seen
#define mailstream_perm_deleted(stream) stream->perm_deleted
#define mailstream_perm_flagged(stream) stream->perm_flagged
#define mailstream_perm_answered(stream) stream->perm_answered
#define mailstream_perm_draft(stream) stream->perm_draft
#define mailstream_kwd_create(stream) stream->kwd_create
#define mailstream_nmsgs(stream) stream->nmsgs
#define mailstream_recent(stream) stream->recent
#define mailstream_uid_validity(stream) stream->uid_validity
#define mailstream_uid_last(stream) stream->uid_last


char *
mailstream_mailbox(stream)
	Mail::Cclient	stream

unsigned short
mailstream_use(stream)
	Mail::Cclient stream

unsigned short
mailstream_sequence(stream)
	Mail::Cclient stream

unsigned int
mailstream_rdonly(stream)
	Mail::Cclient stream

unsigned int
mailstream_anonymous(stream)
	Mail::Cclient stream

unsigned int
mailstream_halfopen(stream)
	Mail::Cclient stream

unsigned int
mailstream_secure(stream)
	Mail::Cclient stream

unsigned int
mailstream_tryssl(stream)
	Mail::Cclient stream

unsigned int
mailstream_mulnewsrc(stream)
	Mail::Cclient stream

unsigned int
mailstream_perm_seen(stream)
	Mail::Cclient stream

unsigned int
mailstream_perm_deleted(stream)
	Mail::Cclient stream

unsigned int
mailstream_perm_flagged(stream)
	Mail::Cclient stream

unsigned int
mailstream_perm_answered(stream)
	Mail::Cclient stream

unsigned int
mailstream_perm_draft(stream)
	Mail::Cclient stream

unsigned int
mailstream_kwd_create(stream)
	Mail::Cclient stream

unsigned long
mailstream_nmsgs(stream)
	Mail::Cclient stream

unsigned long
mailstream_recent(stream)
	Mail::Cclient stream

unsigned long
mailstream_uid_validity(stream)
	Mail::Cclient stream

unsigned long
mailstream_uid_last(stream)
	Mail::Cclient stream

void
mailstream_perm_user_flags(stream)
	Mail::Cclient stream
    PREINIT:
	int i;
    PPCODE:
	for (i = 0; i < NUSERFLAGS; i++)
	    if (stream->perm_user_flags & (1 << i))
		XPUSHs(sv_2mortal(newSVpv(stream->user_flags[i], 0)));

MODULE = Mail::Cclient	PACKAGE = Mail::Cclient	PREFIX = mail_

 #
 # Message Data Fetching Functions
 #

void
mail_fetchfast(stream, sequence, ...)
	Mail::Cclient	stream
	char *		sequence
    PREINIT:
	int i;
	long flags = 0;
    PPCODE:
	for (i = 2; i < items; i++) {
	    char *flag = SvPV(ST(i), na);
	    if (strEQ(flag, "uid"))
		flags |= FT_UID;
	    else {
		croak("unknown flag \"%s\" passed to Mail::Cclient::fetchfast",
		      flag);
	    }
	}
	mail_fetchfast_full(stream, sequence, flags);
	ST(0) = &sv_yes;

void
mail_fetchflags(stream, sequence, ...)
	Mail::Cclient	stream
	char *		sequence
    PREINIT:
	int i;
	long flags = 0;
    PPCODE:
	for (i = 2; i < items; i++) {
	    char *flag = SvPV(ST(i), na);
	    if (strEQ(flag, "uid"))
		flags |= FT_UID;
	    else {
		croak("unknown flag \"%s\" passed to"
		      " Mail::Cclient::fetchflags", flag);
	    }
	}
	mail_fetchflags_full(stream, sequence, flags);
	ST(0) = &sv_yes;

void
mail_fetchstructure(stream, msgno, ...)
	Mail::Cclient	stream
	unsigned long	msgno
    PREINIT:
	int i;
	long flags = 0;
	ENVELOPE *e;
	BODY **bodyp = 0;
	BODY *body = 0;
    PPCODE:
	for (i = 2; i < items; i++) {
	    char *flag = SvPV(ST(i), na);
	    if (strEQ(flag, "uid"))
		flags |= FT_UID;
	    else {
		croak("unknown flag \"%s\" passed to"
		      " Mail::Cclient::fetchstructure", flag);
	    }
	}
	if (GIMME == G_ARRAY)
	    bodyp = &body;
	e = mail_fetchstructure_full(stream, msgno, bodyp, flags);
	XPUSHs(sv_2mortal(make_envelope(e)));
	if (GIMME == G_ARRAY)
	    XPUSHs(sv_2mortal(make_body(body)));


void
mail_thread(stream, ...)
	Mail::Cclient   stream
    PREINIT:
	char *threading = "";
	char *cs = NIL;
	char *search_criteria = NIL;
	SEARCHPGM *spg = NIL;
	THREADNODE *thread;
	int i;
	long flags = 0;
    PPCODE:
	if(items > 9 || floor(fmod(items+1, 2)))
	    croak("Wrong numbers of args (KEY => value)"
		" passed to Mail::Cclient::thread");
	for(i = 1; i < items; i = i + 2) {
	    char *key = SvPV(ST(i), na);
	    if(strcaseEQ(key, "threading"))
		threading = SvPV(ST(i+1), na);
	    else if(strcaseEQ(key, "charset"))
		cs = SvPV(ST(i+1), na);
	    else if(strcaseEQ(key, "search"))
		search_criteria = SvPV(ST(i+1), na);
	    else if(strcaseEQ(key, "flag")) {
		char *flag = SvPV(ST(i+1), na);		
		if (strEQ(flag, "uid"))
		    flags |= SE_UID;
		else
		    croak("unknown FLAG => \"%s\" value passed to"
			" Mail::Cclient::thread", flag);
	    } else
		 croak("unknown \"%s\" keyword passed to"
			" Mail::Cclient::thread", key);
	}
	spg = (search_criteria) ?
		make_criteria(search_criteria) : mail_newsearchpgm();
	thread = mail_thread(stream, (strEQ(threading, "references")) ?
			    "REFERENCES" : "ORDEREDSUBJECT", cs, spg, flags);
	if(thread) {
	    XPUSHs(sv_2mortal(newRV_noinc((SV*)make_thread(thread))));
	    mail_free_threadnode(&thread);
	}
	if(spg) mail_free_searchpgm(&spg);


void
mail_sort(stream, ...)
		Mail::Cclient	stream
	PREINIT:
		char *cs = NIL;
		char *search_criteria = NIL;
		AV *array;
		SEARCHPGM *spg = NIL;
		SORTPGM *pgm = NIL, *pg = NIL;
		unsigned long *slst;
		I32 idx;
		I32 len = 0;
		int i;
		long flags = 0;
	PPCODE:
		if(items < 3 || items > 9 || floor(fmod(items+1, 2)))
			croak("Wrong numbers of args (KEY => value)"
				" passed to Mail::Cclient::sort");
		for(i = 1; i < items; i = i + 2) {
			char *key = SvPV(ST(i), na);
			if(strcaseEQ(key, "sort")) {
				SV *arrayRef = ST(i+1);
				if(SvROK(arrayRef) && SvTYPE(SvRV(arrayRef))) {
					array = (AV*)SvRV(arrayRef);
					len = av_len(array) + 1;
					if(floor(fmod(len, 2)) || !len)
						croak("SORT => wrong numbers of elements in array ref"
							" passed to Mail::Cclient::sort");
					if(len > MAX_LEN_ARRAY)
						croak("SORT => max length of elements exceeded in array ref"
							" passed to Mail::Cclient::sort");
				} else
					croak("SORT => not array ref"
						" passed to Mail::Cclient::sort");
			} else if(strcaseEQ(key, "charset"))
				cs = SvPV(ST(i+1), na);
			else if(strcaseEQ(key, "search"))
				search_criteria = SvPV(ST(i+1), na);
			else if(strcaseEQ(key, "flag")) {
				AV *avflags;
				int k;
				SV *svflags = ST(i+1);
				if(SvROK(svflags) && SvTYPE(SvRV(svflags)))
					avflags = (AV*)SvRV(svflags);
				else {
					avflags = newAV();
					av_push(avflags, svflags);
				}
				for (k = 0; k < av_len(avflags) + 1; k++) {
					SV **allflags = av_fetch(avflags, k, 0);
					char *flag = SvPV(*allflags, na);
					if(strEQ(flag, "uid"))
						flags |= SE_UID;
					else if(strEQ(flag, "searchfree"))
						flags |= SE_FREE;
					else if(strEQ(flag, "noprefetch"))
						flags |= SE_NOPREFETCH;
					else if(strEQ(flag, "sortfree"))
						flags |= SO_FREE;
					else
						croak("unknown FLAG => \"%s\" value passed to"
							" Mail::Cclient::sort", flag);
				}
				if(flags) av_undef(avflags);
			} else
				croak("unknown \"%s\" keyword passed to"
					" Mail::Cclient::sort", key);
		}
		if(!len)
			croak("no SORT key/value passed to Mail::Cclient::sort");
		spg = (search_criteria) ?
			make_criteria(search_criteria) : mail_newsearchpgm();

		for(idx = 0; idx < len; idx = idx+2) {
			SV **n;
			char *criteria = "";
			SV **elem = av_fetch(array, idx, 0);

			if(pg) pg = pg->next = mail_newsortpgm();
			else pgm = pg = mail_newsortpgm();

			if(SvPOKp(*elem)) criteria = SvPV(*elem, na);
			pg->function = (strEQ(criteria, "subject"))
						? SORTSUBJECT
						: (strEQ(criteria, "from"))
							? SORTFROM
							: (strEQ(criteria, "to"))
								? SORTTO
								: (strEQ(criteria, "cc"))
									? SORTCC
									: (strEQ(criteria, "date"))
										? SORTDATE
										: (strEQ(criteria, "size"))
											? SORTSIZE
											: SORTARRIVAL;
			n = av_fetch(array, idx+1, 0);
			pg->reverse = (SvIOK(*n)) ? SvIV(*n) : NIL;
		}
		slst = mail_sort(stream, cs, spg, pgm, flags);
		if(spg) mail_free_searchpgm(&spg);
		if(slst != NIL && slst != 0) {
			XPUSHs(sv_2mortal(newRV_noinc((SV*)make_sort(slst))));
			fs_give ((void **) &slst);
		}
		av_undef(array);
		safefree(pgm);


void
mail_fetchheader(stream, msgno, ...)
	Mail::Cclient	stream
	unsigned long	msgno
    PREINIT:
	int i;
	long flags = 0;
	STRINGLIST *lines = 0;
	unsigned long len;
	char *hdr;
    PPCODE:
	for (i = 2; i < items; i++) {
	    SV *sv = ST(i);
	    if (SvROK(sv)) {
		sv = (SV*)SvRV(sv);
		if (SvTYPE(sv) != SVt_PVAV) {
		    croak("reference to non-list passed to"
			  " Mail::Cclient::fetchheader");
		}
		lines = av_to_stringlist((AV*)sv);
	    }
	    else {
		char *flag = SvPV(sv, na);
		if (strEQ(flag, "uid"))
		    flags |= FT_UID;
		else if (strEQ(flag, "not"))
		    flags |= FT_NOT;
		else if (strEQ(flag, "internal"))
		    flags |= FT_INTERNAL;
		else if (strEQ(flag, "prefetchtext"))
		    flags |= FT_PREFETCHTEXT;
		else {
		    croak("unknown flag \"%s\" passed to"
			  " Mail::Cclient::fetchheader", flag);
		}
	    }
	}
	hdr = mail_fetchheader_full(stream, msgno, lines, &len, flags);
	XPUSHs(sv_2mortal(newSVpv(hdr, len)));
	if(lines)
	    mail_free_stringlist(&lines);

void
mail_fetchtext(stream, msgno, ...)
	Mail::Cclient	stream
	unsigned long	msgno
    PREINIT:
	int i;
	long flags = 0;
	unsigned long len;
	char *text;
    PPCODE:
	for (i = 2; i < items; i++) {
	    char *flag = SvPV(ST(i), na);
	    if (strEQ(flag, "uid"))
		flags |= FT_UID;
	    else if (strEQ(flag, "peek"))
		flags |= FT_PEEK;
	    else if (strEQ(flag, "internal"))
		flags |= FT_INTERNAL;
	    else {
		croak("unknown flag \"%s\" passed to"
		      " Mail::Cclient::fetchtext", flag);
	    }
	}
	text = mail_fetchtext_full(stream, msgno, &len, flags);
	XPUSHs(sv_2mortal(newSVpv(text, len)));

void
mail_fetchbody(stream, msgno, section, ...)
	Mail::Cclient	stream
	unsigned long	msgno
	char *		section
    PREINIT:
	int i;
	long flags = 0;
	unsigned long len;
	char *body;
    PPCODE:
	for (i = 3; i < items; i++) {
	    char *flag = SvPV(ST(i), na);
	    if (strEQ(flag, "uid"))
		flags |= FT_UID;
	    else if (strEQ(flag, "peek"))
		flags |= FT_PEEK;
	    else if (strEQ(flag, "internal"))
		flags |= FT_INTERNAL;
	    else {
		croak("unknown flag \"%s\" passed to Mail::Cclient::fetchbody",
		      flag);
	    }
	}
	body = mail_fetchbody_full(stream, msgno, section, &len, flags);
	XPUSHs(sv_2mortal(newSVpv(body, len)));


unsigned long
mail_uid(stream, msgno)
	Mail::Cclient	stream
	unsigned long	msgno


unsigned long
mail_msgno (stream, uid)
	Mail::Cclient   stream
	unsigned long   uid


void
mail_elt(stream, msgno)
	Mail::Cclient	stream
	unsigned long	msgno
    PREINIT:
	MESSAGECACHE *elt;
    PPCODE:
	elt = mail_elt(stream, msgno);
	XPUSHs(elt ? sv_2mortal(make_elt(stream, elt)) : &sv_undef);

 #
 # Message Status Manipulation Functions
 #

void
mail_setflag(stream, sequence, flag, ...)
		Mail::Cclient	stream
		char *			sequence
		char *			flag
	PREINIT:
		int i;
		long flags = 0;
	ALIAS:
		clearflag = 1
	CODE:
		for(i = 3; i < items; i++) {
			char *fl = SvPV(ST(i), na);
			if(strEQ(fl, "uid"))
				flags |= ST_UID;
			else if (strEQ(fl, "silent"))
				flags |= ST_SILENT;
			else {
				croak("unknown flag \"%s\" passed to Mail::Cclient::%s",
					fl, ix == 1 ? "setflag" : "clearflag");
			}
		}
		if(ix == 1)
			mail_clearflag_full(stream, sequence, flag, flags);
		else
			mail_setflag_full(stream, sequence, flag, flags);


 #
 # Miscellaneous Mailbox and Message Functions
 #

long
mail_ping(stream)
	Mail::Cclient	stream

void
mail_check(stream)
	Mail::Cclient	stream

void
mail_expunge(stream)
	Mail::Cclient	stream

long
mail_copy(stream, sequence, mailbox, ...)
	Mail::Cclient	stream
	char *		sequence
	char *		mailbox
    ALIAS:
	move = 1
    PREINIT:
	int i;
	long flags = 0;
    CODE:
	for (i = 3; i < items; i++) {
	    char *flag = SvPV(ST(i), na);
	    if (strEQ(flag, "uid"))
		flags |= CP_UID;
	    else if (strEQ(flag, "move"))
		flags |= CP_MOVE;
	    else {
		croak("unknown flag \"%s\" passed to Mail::Cclient::%s",
		      flag, ix == 1 ? "move" : "copy");
	    }
	}
	if (ix == 1)
	    flags |= CP_MOVE;
	RETVAL = mail_copy_full(stream, sequence, mailbox, flags);
    OUTPUT:
	RETVAL

 #
 # mail_append slightly tweaked from code submitted by
 # Kevin Sullivan <ksulliva@kludge.psc.edu>.
 #

long
mail_append(stream, mailbox, message, date = 0, flags = 0)
	Mail::Cclient	stream
	char *		mailbox
	SV *		message
	char *		date
	char *		flags
    PREINIT:
	STRING s;
	char *str;
	STRLEN len;
    CODE:
	str = SvPV(message, len);
	CCLIENT_LOCAL_INIT(&s, mail_string, (void *)str, len);
	RETVAL = mail_append_full(stream, mailbox, date, flags, &s);
     OUTPUT:
	RETVAL

void
mail_search(stream, ...)
	Mail::Cclient	stream
    PREINIT:
	SEARCHPGM *spgm = NIL;
	char *search_criteria = NIL;
	char *cs = NIL;
	int i;
	long flags = 0;
    CODE:
	if(items < 3 || items > 7 || floor(fmod(items+1, 2)))
	    croak("Wrong numbers of args (KEY => value)"
		" passed to Mail::Cclient::search");
	for(i = 1; i < items; i = i + 2) {
	    char *key = SvPV(ST(i), na);
	    if(strcaseEQ(key, "search"))
		search_criteria = SvPV(ST(i+1), na);
	    else if(strcaseEQ(key, "charset"))
		cs = SvPV(ST(i+1), na);
	    else if(strcaseEQ(key, "flag")) {
		int k;
		AV *avflags;
		SV *svflags = ST(i+1);
		if(SvROK(svflags) && SvTYPE(SvRV(svflags)))
		    avflags = (AV*)SvRV(svflags);
		else {
		    avflags = newAV();
		    av_push(avflags, svflags);
		}
		for (k = 3; k < av_len(avflags) + 1; k++) {
		    SV **allflags = av_fetch(avflags, k, 0);
		    char *flag = SvPV(*allflags, na);
		    if (strEQ(flag, "uid"))
			flags |= SE_UID;
		    else if (strEQ(flag, "searchfree"))
			flags |= SE_FREE;
		    else if (strEQ(flag, "noprefetch"))
			flags |= SE_NOPREFETCH;
		    else
			croak("unknown FLAG => \"%s\" value passed to"
				" Mail::Cclient::search", flag);
		}
		if(flags) av_undef(avflags);
	    } else
		croak("unknown \"%s\" keyword passed to"
			" Mail::Cclient::search", key);
	}
	if(!search_criteria)
	    croak("no SEARCH key/value passed to Mail::Cclient::search");
	if(spgm = make_criteria(search_criteria))
		mail_search_full(stream, cs, spgm, flags);


unsigned long
mail_filter(stream, ...)
		Mail::Cclient	stream
	PREINIT:	
		STRINGLIST *lines = 0;
		STRLEN len = 0;
		SIZEDTEXT szt;
		MESSAGECACHE *mc;
		int i;
		long flags = 0;
		unsigned long msgno;
	CODE:
		if(items < 5 || items > 7 || floor(fmod(items+1, 2)))
			croak("Wrong numbers of args (KEY => value)"
				" passed to Mail::Cclient::filter");

		for(i = 1; i < items; i = i + 2) {
			char *key = SvPV(ST(i), na);
			if(strcaseEQ(key, "msgno")) {
				msgno = (unsigned long)SvUV(ST(i+1));
			} else if(strcaseEQ(key, "lines")) {
				SV *arrayRef = ST(i+1);
				if(SvROK(arrayRef) && SvTYPE(SvRV(arrayRef))) {
					lines = av_to_stringlist((AV*)SvRV(arrayRef));
				}
			} else if(strcaseEQ(key, "flag")) {
				char *flag = SvPV(ST(i+1), na);
				if (strEQ(flag, "not"))
					flags |= FT_NOT;
				else
					croak("unknown FLAG => \"%s\" value passed to"
						" Mail::Cclient::filter", flag);
			}
		}
		mc = mail_elt(stream, msgno);
		memset(&szt, 0, sizeof(SIZEDTEXT));
		textcpy(&szt, &mc->private.msg.header.text);
		mail_filter((char *) szt.data, szt.size, lines, flags);


 #
 # mail_search_msg from code submitted by
 # Helena Gomes <hpgomes@mail.pt>.
 #

long
mail_search_msg(stream, msgno, criteria, cs = NIL)
	Mail::Cclient	stream
	unsigned long	msgno
	char *		criteria
	char *		cs
    PREINIT:
	SEARCHPGM *spgm;
	long result = NIL;
    CODE:
	spgm = make_criteria(criteria);
	if(spgm) result = mail_search_msg(stream, msgno, cs, spgm);
	RETVAL = result;
    OUTPUT:
	RETVAL


void
mail_real_gc(stream, ...)
	Mail::Cclient	stream
    PREINIT:
	int i;
	long flags = 0;
    CODE:
	for (i = 1; i < items; i++) {
	    char *flag = SvPV(ST(i), na);
	    if (strEQ(flag, "elt"))
		flags |= GC_ELT;
	    else if (strEQ(flag, "env"))
		flags |= GC_ENV;
	    else if (strEQ(flag, "texts"))
		flags |= GC_TEXTS;
	    else
		croak("unknown flag \"%s\" passed to Mail::Cclient::gc", flag);
	}
	mail_gc(stream, flags);

 #
 # This is _parameters which handles a single extra argument (equivalent
 # to GET_FOO) or two extra arguments (equivalent to SET_FOO). The
 # "parameters" method in Cclient.pm handles multiple pairs of arguments
 # for SET_.
 #

void
mail__parameters(stream, param, sv = 0)
		Mail::Cclient	stream
		char *			param
		SV *				sv
	PREINIT:
		char *res_str = 0;
		int res_int;
	PPCODE:
		if(strEQ(param, "USERNAME")) {
			if(sv)
				mail_parameters(stream, SET_USERNAME, SvPV(sv, na));
			else
				res_str = mail_parameters(stream, GET_USERNAME, 0);
		} else if(strEQ(param, "HOMEDIR")) {
			if(sv)
				mail_parameters(stream, SET_HOMEDIR, SvPV(sv, na));
			else
				res_str = mail_parameters(stream, GET_HOMEDIR, 0);
		} else if(strEQ(param, "LOCALHOST")) {
			if(sv)
				mail_parameters(stream, SET_LOCALHOST, SvPV(sv, na));
			else
				res_str = mail_parameters(stream, GET_LOCALHOST, 0);
		} else if(strEQ(param, "SYSINBOX")) {
			if(sv)
				mail_parameters(stream, SET_SYSINBOX, SvPV(sv, na));
			else
				res_str = mail_parameters(stream, GET_SYSINBOX, 0);
		} else if(strEQ(param, "NEWSACTIVE")) {
			if(sv)
				mail_parameters(stream, SET_NEWSACTIVE, SvPV(sv, na));
			else
				res_str = mail_parameters(stream, GET_NEWSACTIVE, 0);
		} else if (strEQ(param, "NEWSSPOOL")) {
			if(sv)
				mail_parameters(stream, SET_NEWSSPOOL, SvPV(sv, na));
			else
				res_str = mail_parameters(stream, GET_NEWSSPOOL, 0);
		} else if(strEQ(param, "NEWSRC")) {
			if(sv)
				mail_parameters(stream, SET_NEWSRC, SvPV(sv, na));
			else
				res_str = mail_parameters(stream, GET_NEWSRC, 0);
		} else if(strEQ(param, "ANONYMOUSHOME")) {
			if(sv)
				mail_parameters(stream, SET_ANONYMOUSHOME, SvPV(sv, na));
			else
				res_str = mail_parameters(stream, GET_ANONYMOUSHOME, 0);
		} else if(strEQ(param, "OPENTIMEOUT")) {
			if(sv)
				mail_parameters(stream, SET_OPENTIMEOUT, (void*)SvIV(sv));
			else
				res_int = (int) mail_parameters(stream, GET_OPENTIMEOUT, 0);
		} else if(strEQ(param, "READTIMEOUT")) {
			if(sv)
				mail_parameters(stream, SET_READTIMEOUT, (void*)SvIV(sv));
			else
				res_int = (int) mail_parameters(stream, GET_READTIMEOUT, 0);
		} else if(strEQ(param, "WRITETIMEOUT")) {
			if(sv)
				mail_parameters(stream, SET_WRITETIMEOUT, (void*)SvIV(sv));
			else
				res_int = (int) mail_parameters(stream, GET_WRITETIMEOUT, 0);
		} else if(strEQ(param, "CLOSETIMEOUT")) {
			if(sv)
				mail_parameters(stream, SET_CLOSETIMEOUT, (void*)SvIV(sv));
			else
				res_int = (int) mail_parameters(stream, GET_CLOSETIMEOUT, 0);
		} else if(strEQ(param, "RSHTIMEOUT")) {
			if(sv)
				mail_parameters(stream, SET_RSHTIMEOUT, (void*)SvIV(sv));
			else
				res_int = (int) mail_parameters(stream, GET_RSHTIMEOUT, 0);
		} else if(strEQ(param, "SSHTIMEOUT")) {
			if(sv)
				mail_parameters(stream, SET_SSHTIMEOUT, (void*)SvIV(sv));
			else
				res_int = (int) mail_parameters(stream, GET_SSHTIMEOUT, 0);
		} else if(strEQ(param, "SSLFAILURE")) {
			if(sv)
				mail_parameters(stream, SET_SSLFAILURE, (void*)SvIV(sv));
			else
				res_int = (int) mail_parameters(stream, GET_SSLFAILURE, 0);
		} else if(strEQ(param, "MAXLOGINTRIALS")) {
			if(sv)
				mail_parameters(stream, SET_MAXLOGINTRIALS, (void*)SvIV(sv));
			else
				res_int = (int) mail_parameters(stream, GET_MAXLOGINTRIALS, 0);
		} else if(strEQ(param, "LOOKAHEAD")) {
			if(sv)
				mail_parameters(stream, SET_LOOKAHEAD, (void*)SvIV(sv));
			else
				res_int = (int) mail_parameters(stream, GET_LOOKAHEAD, 0);
		} else if(strEQ(param, "IMAPPORT")) {
			if(sv)
				mail_parameters(stream, SET_IMAPPORT, (void*)SvIV(sv));
			else
				res_int = (int) mail_parameters(stream, GET_IMAPPORT, 0);
		} else if(strEQ(param, "PREFETCH")) {
			if(sv)
				mail_parameters(stream, SET_PREFETCH, (void*)SvIV(sv));
			else
				res_int = (int) mail_parameters(stream, GET_PREFETCH, 0);
		} else if(strEQ(param, "CLOSEONERROR")) {
			if(sv)
				mail_parameters(stream, SET_CLOSEONERROR, (void*)SvIV(sv));
			else
				res_int = (int) mail_parameters(stream, GET_CLOSEONERROR, 0);
		} else if(strEQ(param, "POP3PORT")) {
			if(sv)
				mail_parameters(stream, SET_POP3PORT, (void*)SvIV(sv));
			else
				res_int = (int) mail_parameters(stream, GET_POP3PORT, 0);
		} else if(strEQ(param, "UIDLOOKAHEAD")) {
			if(sv)
				mail_parameters(stream, SET_UIDLOOKAHEAD, (void*)SvIV(sv));
			else
				res_int = (int) mail_parameters(stream, GET_UIDLOOKAHEAD, 0);
		} else if(strEQ(param, "MBXPROTECTION")) {
			if(sv)
				mail_parameters(stream, SET_MBXPROTECTION, (void*)SvIV(sv));
			else
				res_int = (int) mail_parameters(stream, GET_MBXPROTECTION, 0);
		} else if(strEQ(param, "DIRPROTECTION")) {
			if(sv)
				mail_parameters(stream, SET_DIRPROTECTION, (void*)SvIV(sv));
			else
				res_int = (int) mail_parameters(stream, GET_DIRPROTECTION, 0);
		} else if(strEQ(param, "LOCKPROTECTION")) {
			if(sv)
				mail_parameters(stream, SET_LOCKPROTECTION, (void*)SvIV(sv));
			else
				res_int = (int) mail_parameters(stream, GET_LOCKPROTECTION, 0);
		} else if(strEQ(param, "FROMWIDGET")) {
			if(sv)
				mail_parameters(stream, SET_FROMWIDGET, (void*)SvIV(sv));
			else
				res_int = (int) mail_parameters(stream, GET_FROMWIDGET, 0);
		} else if(strEQ(param, "DISABLEFCNTLLOCK")) {
			if(sv)
				mail_parameters(stream, SET_DISABLEFCNTLLOCK, (void*)SvIV(sv));
			else
				res_int = (int) mail_parameters(stream, GET_DISABLEFCNTLLOCK, 0);
		} else if(strEQ(param, "LOCKEACCESERROR")) {
			if(sv)
				mail_parameters(stream, SET_LOCKEACCESERROR, (void*)SvIV(sv));
			else
				res_int = (int) mail_parameters(stream, GET_LOCKEACCESERROR, 0);
		} else if(strEQ(param, "LISTMAXLEVEL")) {
			if(sv)
				mail_parameters(stream, SET_LISTMAXLEVEL, (void*)SvIV(sv));
			else
				res_int = (int) mail_parameters(stream, GET_LISTMAXLEVEL, 0);
		} else {
			croak("no such parameter name: %s", param);
		}
		if(sv)
			ST(0) = &sv_yes;
		else {
			if (res_str)
				XPUSHs(sv_2mortal(newSVpv(res_str, 0)));
			else
				XPUSHs(sv_2mortal(newSViv(res_int)));
		}

 #
 # Utility Functions
 #

void
mail_debug(stream)
	Mail::Cclient	stream

void
mail_nodebug(stream)
	Mail::Cclient	stream

#define mail_set_sequence(stream, seq) mail_sequence(stream, seq)

long
mail_set_sequence(stream, sequence)
	Mail::Cclient	stream
	char *		sequence

#define mail_uid_set_sequence(stream, seq) mail_uid_sequence(stream, seq)

long
mail_uid_set_sequence(stream, sequence)
	Mail::Cclient	stream
	char *		sequence


MODULE = Mail::Cclient	PACKAGE = Mail::Cclient::SMTP	PREFIX = smtp_

PROTOTYPES: DISABLE

 #
 # SMTP Functions
 #

Mail::Cclient::SMTP
smtp_open(package="Mail::Cclient::SMTP", svhostlist, debug = 0)
		char *	package
		SV *	svhostlist
		long	debug
	PREINIT:
		int k;
		char **hostlist = NIL;
		AV *avhostlist;
		I32 n;
	CODE:
		if(SvROK(svhostlist) && SvTYPE(SvRV(svhostlist)))
			avhostlist = (AV*)SvRV(svhostlist);
		else {
			avhostlist = newAV();
			av_push(avhostlist, svhostlist);
		}
		n = av_len(avhostlist) + 1;
		hostlist = (char **)safemalloc(n * sizeof(char *));
		for (k = 0; k < n; k++) {
			SV **h = av_fetch(avhostlist, k, 0);
			char *host = SvPV(*h, na);
			hostlist[k] = host;
		}

		RETVAL = smtp_open(hostlist, debug);
		safefree(hostlist);

		if(!RETVAL)
			XSRETURN_UNDEF;
	OUTPUT:
		RETVAL


long
smtp_mail(stream, ...)
		Mail::Cclient::SMTP	stream
	PREINIT:
		ENVELOPE *env = NULL;
		BODY *body = NULL;
		SV *svenv = NULL, *svbody = NULL;
		char *trans = "MAIL";
		char *dhost = "no host";
		PerlIO *fp = NULL;
		int i;
	CODE:
		for(i = 1; i < items; i = i + 2) {
			char *key = SvPV(ST(i), na);
			if(strcaseEQ(key, "defaulthost"))
				dhost = SvPV(ST(i+1), na);
			else if(strcaseEQ(key, "transaction"))
				trans = ucase(SvPV(ST(i+1), na));
			else if(strcaseEQ(key, "filehandle"))
				fp = IoIFP(sv_2io(ST(i+1)));
			else if(strcaseEQ(key, "envelope"))
				svenv = ST(i+1);
			else if(strcaseEQ(key, "body"))
				svbody = ST(i+1);
			else
				croak("unknown \"%s\" keyword passed to"
					" Mail::Cclient::SMTP::smtp_mail", key);
		}
		if(svenv) {
			if(SvROK(svenv) && SvTYPE(SvRV(svenv)) == SVt_PVHV) {
				env = mail_newenvelope();
				make_mail_envelope(env, dhost, (HV*)SvRV(svenv));
			} else {
				croak("envelope is not hash reference");
				XSRETURN_UNDEF;
			}
		} else {
			croak("no such envelope hash reference");
			XSRETURN_UNDEF;
		}

		if(svbody) {
			if(SvROK(svbody) && SvTYPE(SvRV(svbody)) == SVt_PVHV) {
				body = mail_newbody();
				make_mail_body(body, (HV*)SvRV(svbody));
			} else {
				croak("body is not hash reference");
				XSRETURN_UNDEF;
			}
		} else {
			croak("no such body hash reference");
			XSRETURN_UNDEF;
		}
		RETVAL = smtp_mail(stream, trans, env, body);
		if(fp) save_rfc822_tmp(env, body, fp);

	OUTPUT:
		RETVAL


void
smtp_debug(stream, ...)
		Mail::Cclient::SMTP	stream
	CODE:
		stream->debug = T;


void
smtp_nodebug(stream, ...)
		Mail::Cclient::SMTP	stream
	CODE:
		stream->debug = NIL;

void
smtp_close(stream, ...)
		Mail::Cclient::SMTP	stream
	CODE:
		smtp_close(stream);


MODULE = Mail::Cclient	PACKAGE = Mail::Cclient

 #
 # MIME type conversion functions
 #

void
rfc822_base64(source)
		SV *	source
	PREINIT:
		STRLEN srcl;
		unsigned long len;
		unsigned char *s;
	PPCODE:
		s = (unsigned char*)SvPV(source, srcl);
		s = rfc822_base64(s, (unsigned long)srcl, &len);
		XPUSHs(sv_2mortal(newSVpv((char*)s, (STRLEN)len)));

void
rfc822_qprint(source)
		SV *	source
	PREINIT:
		STRLEN srcl;
		unsigned long len;
		unsigned char *s;
	PPCODE:
		s = (unsigned char*)SvPV(source, srcl);
		s = rfc822_qprint(s, (unsigned long)srcl, &len);
		XPUSHs(sv_2mortal(newSVpv((char*)s, (STRLEN)len)));


void            
utf8_mime2text(source)
		SV *	source
	PREINIT:
		SIZEDTEXT src;
		SIZEDTEXT dst;
		STRLEN srcl;  
		unsigned char *ptr;
	PPCODE:
		ptr = (unsigned char*)SvPV(source, srcl);
		src.data = ptr;
		src.size = (unsigned long)srcl;
		utf8_mime2text(&src, &dst);   
		XPUSHs(sv_2mortal(newSVpv((char*)dst.data, (STRLEN)dst.size)));

 #
 # Utility functions
 #

char *
rfc822_date()
	PREINIT:
		static char date[DATE_BUFF_SIZE];
	CODE:
		rfc822_date(date);
		RETVAL = date;
	OUTPUT:
		RETVAL

void
rfc822_parse_adrlist(string, host)
		char *  string
		char *  host  
	PREINIT:
		ENVELOPE *env;
	PPCODE:
		env = mail_newenvelope();
		rfc822_parse_adrlist(&env->to, string, host);
		XPUSHs(env->to ?
			sv_2mortal(newRV_noinc((SV*)make_address(env->to))) : &sv_undef);


char *
rfc822_write_address(mailbox, host, personal)
		char *  mailbox
		char *  host
		char *  personal
	PREINIT:
		ADDRESS *addr;
		char string[MAILTMPLEN];
	CODE:
		addr = mail_newaddr();
		addr->mailbox = mailbox;
		addr->host = host;
		addr->personal = personal;
		addr->next=NIL;
		addr->error=NIL;
		addr->adl=NIL;
		string[0]='\0';
		rfc822_write_address(string, addr);
		RETVAL = string;
	OUTPUT:
		RETVAL


long
rfc822_output(...)
	PREINIT:
		char tmp[8*MAILTMPLEN];
		ENVELOPE *env = NULL;
		BODY *body = NULL;
		SV *svenv = NULL, *svbody = NULL;
		char *dhost = "no host";
		PerlIO *fp = NULL;
		int i;
	CODE:
		for(i = 0; i < items; i = i + 2) {
			char *key = SvPV(ST(i), na);
			if(strcaseEQ(key, "defaulthost"))
				dhost = SvPV(ST(i+1), na);
			else if(strcaseEQ(key, "filehandle"))
				fp = IoIFP(sv_2io(ST(i+1)));
			else if(strcaseEQ(key, "envelope"))
				svenv = ST(i+1);
			else if(strcaseEQ(key, "body"))
				svbody = ST(i+1);   
			else
				croak("unknown \"%s\" keyword passed to"
					" Mail::Cclient::rfc822_output",key);
		}
		if(svenv) {
			if(SvROK(svenv) && SvTYPE(SvRV(svenv)) == SVt_PVHV) {
				env = mail_newenvelope();
				make_mail_envelope(env, dhost, (HV*)SvRV(svenv));
			} else {
				croak("envelope is not hash reference");
				XSRETURN_UNDEF;  
			}
		} else {
			croak("no such envelope hash reference");
			XSRETURN_UNDEF;
		}
		if(svbody) {
			if(SvROK(svbody) && SvTYPE(SvRV(svbody)) == SVt_PVHV) {
				body = mail_newbody();
				make_mail_body(body, (HV*)SvRV(svbody));
			} else {
				croak("body is not hash reference");
				XSRETURN_UNDEF;
			}
		} else {
			croak("no such body hash reference");
			XSRETURN_UNDEF;
		}
		RETVAL = rfc822_output(tmp, env, body, transfer, fp, 1);
	OUTPUT:
		RETVAL


BOOT:
#include "linkage.c"
	mailstream2sv = newHV();
	stash_Cclient = gv_stashpv("Mail::Cclient", TRUE);
	stash_Address = gv_stashpv("Mail::Cclient::Address", TRUE);
	stash_Envelope = gv_stashpv("Mail::Cclient::Envelope", TRUE);
	stash_Body = gv_stashpv("Mail::Cclient::Body", TRUE);
	stash_Elt = gv_stashpv("Mail::Cclient::Elt", TRUE);
	callback = perl_get_hv("Mail::Cclient::_callback", TRUE);
	address_fields = newRV((SV*)perl_get_hv("Mail::Cclient::"
						"Address::FIELDS", TRUE));
	envelope_fields = newRV((SV*)perl_get_hv("Mail::Cclient::"
						 "Envelope::FIELDS", TRUE));
	body_fields = newRV((SV*)perl_get_hv("Mail::Cclient::Body::FIELDS",
					     TRUE));
	elt_fields = newRV((SV*)perl_get_hv("Mail::Cclient::Elt::FIELDS",
					    TRUE));
