/*
 * Program:	Mailbox Access routines
 *		Extension of mail_criteria function
 *
 * Author:	Helena Gomes <hpgomes@mail.pt>
 * Date:	18 July 2001
 * Last Edited:	15 October 2001
 *
 * Parts of code from sources of c-client (Mark Crispin)
 * Copyright 2001 University of Washington.
 */

#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include "mail.h"
#include "misc.h"
#include "criteria.h"

#define LITSTKLEN	20
#define MAXCLIENTLIT	10000
#define TMPLEN		8192

int litsp = 0;
char *litstk[LITSTKLEN];
char cmdbuf[TMPLEN];

long _parse_criteria(SEARCHPGM *pgm, char **arg, unsigned long maxmsg,
				unsigned long maxuid, unsigned long depth) {
	if(arg && *arg) {
		do
			if(!_parse_criterion(pgm, arg, maxmsg, maxuid, depth))
				return NIL;
		while (**arg == ' ' && (*arg)++);
		if(**arg && **arg != ')') return NIL;
	}
	return T;
}

long _parse_criterion(SEARCHPGM *pgm, char **arg, unsigned long maxmsg,
				unsigned long maxuid, unsigned long depth) {
	unsigned long i;
	char c = NIL, *s, *t, *v, *tail, *del;  
	SEARCHSET **set;
	SEARCHPGMLIST **not;
	SEARCHOR **or;
	SEARCHHEADER **hdr;
	long ret = NIL;

	if((depth > 50) || !(arg && *arg));
	else if(**arg == '(') {
		(*arg)++;
		if(_parse_criteria(pgm, arg, maxmsg, maxuid, depth+1) && **arg == ')') {
			(*arg)++;
			ret = T;
		}
	} else {
		if(!(tail = strpbrk((s = *arg)," )"))) tail = *arg + strlen (*arg);
		c = *(del = tail);
		*del = '\0';

		switch(*ucase(s)) {
		case '*':
		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			if(*(set = &pgm->msgno)) {
				for(not = &pgm->not; *not; not = &(*not)->next);
				*not = mail_newsearchpgmlist();
				set = &((*not)->pgm->not = mail_newsearchpgmlist())->pgm->msgno;
			}
			ret = _crit_set(set, &s, maxmsg) && (tail == s);
			break;
		case 'A': /* possible ALL, ANSWERED */
			if(!strcmp(s+1,"LL")) ret = T;
			else if(!strcmp(s+1,"NSWERED")) ret = pgm->answered = T;
			break;

		case 'B': /* possible BCC, BEFORE, BODY */
			if(!strcmp(s+1,"CC") && c == ' ' && *++tail)
				ret = _crit_string(&pgm->bcc,&tail);
			else if(!strcmp(s+1,"EFORE") && c == ' ' && *++tail)
				ret = _crit_date(&pgm->before,&tail);
			else if(!strcmp(s+1,"ODY") && c == ' ' && *++tail)
				ret = _crit_string(&pgm->body,&tail);
			break;
		case 'C': /* possible CC */
			if(!strcmp(s+1,"C") && c == ' ' && *++tail)
				ret = _crit_string(&pgm->cc,&tail);
			break;
		case 'D': /* possible DELETED */
			if(!strcmp(s+1,"ELETED")) ret = pgm->deleted = T;
			if(!strcmp(s+1,"RAFT")) ret = pgm->draft = T;
			break;
		case 'F':  /* possible FLAGGED, FROM */
			if(!strcmp(s+1,"LAGGED")) ret = pgm->flagged = T;
			else if(!strcmp(s+1,"ROM") && c == ' ' && *++tail)
				ret = _crit_string(&pgm->from,&tail);
			break;
		case 'H': /* possible HEADER */
			if(!strcmp(s+1,"EADER") && c == ' ' && *(v = tail + 1) &&
				(s = _parse_astring(&v, &i, &c)) && i && c == ' ' &&
					(t = _parse_astring (&v, &i, &c))) {
				for(hdr = &pgm->header; *hdr; hdr = &(*hdr)->next);
				*hdr = mail_newsearchheader(s,t);
				*(tail = v ? v - 1 : t + i) = c;
				ret = T;
			}
			break;
		case 'K': /* possible KEYWORD */
			if(!strcmp(s+1,"EYWORD") && c == ' ' && *++tail)
				ret = _crit_string (&pgm->keyword,&tail);
			break;
		case 'L': /* possible LARGER */
			if(!strcmp(s+1,"ARGER") && c == ' ' && *++tail)
				ret = _crit_number(&pgm->larger,&tail);
			break;
		case 'N': /* possible NEW, NOT */
			if(!strcmp(s+1,"EW")) ret = pgm->recent = pgm->unseen = T;
			else if(!strcmp(s+1,"OT") && c == ' ' && *++tail) {
				for(not = &pgm->not; *not; not = &(*not)->next);
				*not = mail_newsearchpgmlist();
				ret = _parse_criterion((*not)->pgm, &tail, maxmsg, maxuid, depth+1);
			}
			break;
		case 'O': /* possible OLD, ON */
			if(!strcmp(s+1,"LD")) ret = pgm->old = T;
			else if(!strcmp(s+1,"N") && c == ' ' && *++tail)
				ret = _crit_date(&pgm->on,&tail);
			else if(!strcmp(s+1,"R") && c == ' ') {
				for(or = &pgm->or; *or; or = &(*or)->next);
				*or = mail_newsearchor();
				ret = *++tail && _parse_criterion((*or)->first,&tail,maxmsg,maxuid,depth+1) &&
					*tail == ' ' && *++tail && _parse_criterion((*or)->second,&tail,maxmsg,maxuid,depth+1);
			}
			break;
		case 'R': /* possible RECENT */
			if(!strcmp (s+1,"ECENT")) ret = pgm->recent = T;
			break;
		case 'S': /* possible SEEN, SINCE, SUBJECT */
			if(!strcmp(s+1,"EEN")) ret = pgm->seen = T;
			else if(!strcmp(s+1,"ENTBEFORE") && c == ' ' && *++tail)
				ret = _crit_date(&pgm->sentbefore,&tail);
			else if(!strcmp(s+1,"ENTON") && c == ' ' && *++tail)
				ret = _crit_date(&pgm->senton,&tail);
			else if(!strcmp(s+1,"ENTSINCE") && c == ' ' && *++tail)
				ret = _crit_date(&pgm->sentsince,&tail);
			else if(!strcmp(s+1,"INCE") && c == ' ' && *++tail)
				ret = _crit_date(&pgm->since,&tail);
			else if(!strcmp(s+1,"MALLER") && c == ' ' && *++tail)
				ret = _crit_number(&pgm->smaller,&tail);
			else if(!strcmp(s+1,"UBJECT") && c == ' ' && *++tail)
				ret = _crit_string(&pgm->subject,&tail);
			break;
		case 'T': /* possible TEXT, TO */
			if(!strcmp(s+1,"EXT") && c == ' ' && *++tail)
				ret = _crit_string(&pgm->text, &tail);
			else if(!strcmp(s+1,"O") && c == ' ' && *++tail)
				ret = _crit_string(&pgm->to, &tail);
			break;
		case 'U': /* possible UID, UN* */
			if(!strcmp(s+1,"ID") && c== ' ' && *++tail) {
				if(*(set = &pgm->uid)) {
					for(not = &pgm->not; *not; not = &(*not)->next);
					*not = mail_newsearchpgmlist();
					set = &((*not)->pgm->not = mail_newsearchpgmlist ())->pgm->uid;
				}
				ret = _crit_set(set, &tail, maxuid);
			} else if(!strcmp(s+1,"NANSWERED")) ret = pgm->unanswered = T;
			else if(!strcmp(s+1,"NDELETED")) ret = pgm->undeleted = T;
			else if(!strcmp(s+1,"NDRAFT")) ret = pgm->undraft = T;
			else if(!strcmp(s+1,"NFLAGGED")) ret = pgm->unflagged = T;
			else if(!strcmp(s+1,"NKEYWORD") && c == ' ' && *++tail)
				ret = _crit_string(&pgm->unkeyword, &tail);
			else if(!strcmp(s+1,"NSEEN")) ret = pgm->unseen = T;
			break;
		default:
			break;
		}
		if(ret) {
			*del = c;
			*arg = tail;
		}
	}
	return ret;
}

long _crit_date(unsigned short *date, char **arg) {
	if(**arg != '"') return _crit_date_work(date, arg);   
	(*arg)++;
	if(!(_crit_date_work(date,arg) && (**arg == '"'))) return NIL;
	(*arg)++;                                               
	return T;
}

long _crit_date_work(unsigned short *date, char **arg) {
	int d,m,y;
	if(isdigit(d = *(*arg)++) || ((d == ' ') && isdigit(**arg))) {
		if(d == ' ') d = 0;
		else d -= '0';
		if(isdigit(**arg)) {
			d *= 10;
			d += *(*arg)++ - '0';
		}
		if((**arg == '-') && (y = *++(*arg))) {
			m = (y >= 'a' ? y - 'a' : y - 'A') * 1024;
			if((y = *++(*arg))) {
				m += (y >= 'a' ? y - 'a' : y - 'A') * 32;
				if((y = *++(*arg))) {
					m += (y >= 'a' ? y - 'a' : y - 'A');
					switch(m) {
					case(('J'-'A') * 1024) + (('A'-'A') * 32) + ('N'-'A'): m = 1; break;
					case(('F'-'A') * 1024) + (('E'-'A') * 32) + ('B'-'A'): m = 2; break;
					case(('M'-'A') * 1024) + (('A'-'A') * 32) + ('R'-'A'): m = 3; break;
					case(('A'-'A') * 1024) + (('P'-'A') * 32) + ('R'-'A'): m = 4; break;
					case(('M'-'A') * 1024) + (('A'-'A') * 32) + ('Y'-'A'): m = 5; break;
					case(('J'-'A') * 1024) + (('U'-'A') * 32) + ('N'-'A'): m = 6; break;
					case(('J'-'A') * 1024) + (('U'-'A') * 32) + ('L'-'A'): m = 7; break;
					case(('A'-'A') * 1024) + (('U'-'A') * 32) + ('G'-'A'): m = 8; break;
					case(('S'-'A') * 1024) + (('E'-'A') * 32) + ('P'-'A'): m = 9; break;
					case(('O'-'A') * 1024) + (('C'-'A') * 32) + ('T'-'A'): m = 10;break;
					case(('N'-'A') * 1024) + (('O'-'A') * 32) + ('V'-'A'): m = 11;break; 
					case(('D'-'A') * 1024) + (('E'-'A') * 32) + ('C'-'A'): m = 12;break;   
					default: return NIL;
					}
					if((*++(*arg) == '-') && isdigit (*++(*arg))) {
						y = 0;
						do {
							y *= 10;
							y += *(*arg)++ - '0';
						} while(isdigit(**arg));
						if(d < 1 || d > 31 || m < 1 || m > 12 || y < 0) return NIL;
						if(y < 100) y += (y >= (BASEYEAR - 1900)) ? 1900 : 2000;
						*date = ((y - BASEYEAR) << 9) + (m << 5) + d;
						return T;
					}
				}
			}
		}
	}
	return NIL;
}


long _crit_string(STRINGLIST **string, char **arg) {
	unsigned long i;
	char c;
	char *s = _parse_astring(arg, &i, &c);

	if(!s) return NIL;

	while (*string) string = &(*string)->next;
	*string = mail_newstringlist ();
	(*string)->text.data = (unsigned char *) fs_get (i + 1);
	memcpy((*string)->text.data,s,i);
	(*string)->text.data[i] = '\0';  
	(*string)->text.size = i;

	if(!*arg) *arg = (char *) (*string)->text.data + i;
	else (*--(*arg) = c);

	return T;
}

char *_parse_astring(char **arg, unsigned long *size, char *del) {
	unsigned long i;
	char c,*s,*t,*v;

	if(!*arg) return NIL;
	switch(**arg) {
	default:
		for (s = t = *arg, i = 0;
			(*t > ' ') && (*t < 0x7f) && (*t != '(') && (*t != ')') &&
				(*t != '{') && (*t != '%') && (*t != '*') && (*t != '"') &&
					(*t != '\\'); ++t,++i);
		if(*size = i)
			break;
	case ')': case '%': case '*': case '\\': case '\0': case ' ':
		return NIL;
	case '"':
		for(s = t = v = *arg + 1; (c = *t++) != '"'; *v++ = c) {
			if(c == '\\') c = *t++;
			if(!c || (c & 0x80)) return NIL;
		}
		*v = '\0';
		*size = v - s;
		break;
	case '{':
		s = *arg + 1;
		if(!isdigit (*s)) return NIL;
		if((*size = i = strtoul(s,&t,10)) > MAXCLIENTLIT) {
			mm_notify(NIL,"Absurdly long client literal",ERROR);
			return NIL;
		}
		if(!t || (*t != '}') || t[1]) return NIL;
		if(litsp >= LITSTKLEN) {
			mm_notify(NIL,"Too many literals in command",ERROR);
			return NIL;
		}
		_inliteral(s = litstk[litsp++] = (char *) fs_get(i+1),i);
		_slurp(*arg = t,TMPLEN - (t - cmdbuf));
		if(!strchr(t, '\012')) return NIL;
		if(!strtok(t, "\015\012")) *t = '\0';
		break;
	}
	if(*del = *t) {
		*t++ = '\0';   
		*arg = t;
	}
	else *arg = NIL;
	return s;
}

void _inliteral(char *s, unsigned long n) {
	/* warning, this need some debug */
	s[n] = '\0';
}

void _slurp(char *s, int n) {
	/* warning, this need some debug */
	s[--n] = '\0';
}

long _crit_set(SEARCHSET **set, char **arg, unsigned long maxima) {
	unsigned long i;

	*set = mail_newsearchset();
	if (**arg == '*') {
		(*arg)++;
		(*set)->first = maxima;
	} else if(_crit_number(&i, arg) && i) (*set)->first = i;
	else return NIL;

	switch(**arg) {
	case ':':
		if(*++(*arg) == '*') {
			(*arg)++;
			(*set)->last -= maxima;
		} else if(_crit_number(&i,arg) && i) {
			if(i < (*set)->first) {
				(*set)->last = (*set)->first;
				(*set)->first = i;
			} else (*set)->last = i;
		} else return NIL;
		if(**arg != ',')
			break;
	case ',':
		(*arg)++;
		return _crit_set(&(*set)->next, arg, maxima);
	default:
		break;
	}
	return T;
}

long _crit_number(unsigned long *number, char **arg) {
	if(!isdigit (**arg)) return NIL;
	*number = 0;
	while (isdigit (**arg)) {
		*number *= 10;                            
		*number += *(*arg)++ - '0';                       
	}
	return T;
}

SEARCHPGM *make_criteria(char *criteria) {
	SEARCHPGM *spgm;

	if(!criteria) return NIL;
	_parse_criteria(spgm = mail_newsearchpgm(), &criteria, 0, 0, 0);
	return spgm;
}
