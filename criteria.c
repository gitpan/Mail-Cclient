/*
 * Program:	Mailbox Access routines
 *		Extension of mail_criteria function
 *
 * Author:	Helena Gomes <hpgomes@mail.pt>
 * Date:	18 July 2001
 * Last Edited:	23 July 2001
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

#define CRITERIATMPLEN	256

/*
 * Mail parse number into elt field
 * Accepts: elt to write into
 *	    number string to parse
 * Returns: T if parse successful, else NIL 
 */

long _mail_parse_number(MESSAGECACHE *elt, char *s)
{
    unsigned long size = 0;
    char *p = s;

    while(*p) if(!isdigit(*p++)) return NIL;
    elt->rfc822_size = 0;
    size = strtoul((const char *)s, &s, 10);
    elt->rfc822_size = size;
    return T;
}

/*
 * Parse a number 
 * Accepts: pointer to number unsigned long to return
 * Returns: T if successful, else NIL
 */

long _mail_criteria_number (unsigned long *number)
{
    STRINGLIST *s = NIL;
    MESSAGECACHE elt;

    int ret = (mail_criteria_string(&s) &&
	_mail_parse_number(&elt,(char *) s->text.data) &&
		(*number = elt.rfc822_size)) ? T : NIL;
    if(s) mail_free_stringlist(&s);
    return ret;
}

/*
 * Mail parse search criteria
 * Accepts: criteria
 * Returns: search program if parse successful, else NIL
 */

SEARCHPGM *_mail_criteria (char *criteria)  
{
    SEARCHPGM *pgm;
    char tmp[MAILTMPLEN];
    int f = NIL;

    if (!criteria) return NIL;
	pgm = mail_newsearchpgm ();

    for (criteria = strtok (criteria," "); criteria;
	(criteria = strtok (NIL," "))) {
	f = NIL;
	switch (*ucase (criteria)) {
	case 'A':	/* possible ALL, ANSWERED */
	    if(!strcmp (criteria+1,"LL")) f = T;
	    else if(!strcmp (criteria+1,"NSWERED")) f = pgm->answered = T;
	    break;
	case 'B':	/* possible BCC, BEFORE, BODY */
	    if(!strcmp (criteria+1,"CC"))
		f = mail_criteria_string(&pgm->bcc);
	    else if(!strcmp (criteria+1,"EFORE"))
		f = mail_criteria_date(&pgm->before);
	    else if(!strcmp (criteria+1,"ODY"))
		f = mail_criteria_string(&pgm->body);
	    break;
	case 'C':	/* possible CC */
	    if(!strcmp (criteria+1,"C"))
		f = mail_criteria_string(&pgm->cc);
	    break;
	case 'D':	/* possible DELETED, DRAFT */
	    if(!strcmp(criteria+1,"ELETED")) f = pgm->deleted = T;
	    else if(!strcmp(criteria+1,"RAFT")) f = pgm->draft = T;
	    break;
	case 'F':	/* possible FLAGGED, FROM */
	    if(!strcmp (criteria+1,"LAGGED"))
		f = pgm->flagged = T;
	    else if(!strcmp (criteria+1,"ROM"))
		f = mail_criteria_string(&pgm->from);
	    break;
	case 'K':	/* possible KEYWORD */
	    if(!strcmp (criteria+1,"EYWORD"))
		f = mail_criteria_string(&pgm->keyword);
	    break;
	case 'L':	/* possible LARGER */
	    if(!strcmp(criteria+1,"ARGER"))
		f = _mail_criteria_number(&pgm->larger);
	    break;
	case 'N':	/* possible NEW */
	    if(!strcmp (criteria+1,"EW"))
		f = pgm->recent = pgm->unseen = T;
	    break;
	case 'O':	/* possible OLD, ON */
	    if (!strcmp (criteria+1,"LD")) f = pgm->old = T;
	    else if(!strcmp (criteria+1,"N"))
		f = mail_criteria_date(&pgm->on);
	    break;
	case 'R':	/* possible RECENT */
	    if(!strcmp (criteria+1,"ECENT")) f = pgm->recent = T;
	    break;
	case 'S':	/* possible SEEN, SENTBEFORE, SENTON, SENTSINCE, SINCE, SMALLER, SUBJECT */
	    if(!strcmp (criteria+1,"EEN"))
		f = pgm->seen = T;
	    else if(!strcmp (criteria+1,"ENTBEFORE"))
		f = mail_criteria_date(&pgm->sentbefore);
	    else if(!strcmp (criteria+1,"ENTON"))
		f = mail_criteria_date(&pgm->senton);
	    else if(!strcmp (criteria+1,"ENTSINCE"))
		f = mail_criteria_date(&pgm->sentsince);
	    else if(!strcmp (criteria+1,"INCE"))
		f = mail_criteria_date(&pgm->since);
	    else if(!strcmp (criteria+1,"MALLER"))
		f = _mail_criteria_number(&pgm->smaller);
	    else if(!strcmp (criteria+1,"UBJECT"))
		f = mail_criteria_string(&pgm->subject);
	    break;
	case 'T':	/* possible TEXT, TO */
	    if(!strcmp (criteria+1,"EXT"))
		f = mail_criteria_string(&pgm->text);
	    else if(!strcmp (criteria+1,"O"))
		f = mail_criteria_string(&pgm->to);
	    break;
	case 'U':       /* possible UN* */
	    if(criteria[1] == 'N') {
		if(!strcmp (criteria+2,"ANSWERED"))
		    f = pgm->unanswered = T;
		else if(!strcmp (criteria+2,"DELETED"))
		    f = pgm->undeleted = T;
		else if(!strcmp (criteria+2,"DRAFT"))
		    f = pgm->undraft = T;
		else if(!strcmp (criteria+2,"FLAGGED"))
		    f = pgm->unflagged = T;
		else if(!strcmp (criteria+2,"KEYWORD"))
		    f = mail_criteria_string (&pgm->unkeyword);
		else if(!strcmp (criteria+2,"SEEN"))
		    f = pgm->unseen = T;
	    }
	    break;
	default:
	    break;
	}
	if(!f) {
	    sprintf (tmp,"Unknown search criterion: %.30s",criteria);
	    MM_LOG (tmp, ERROR);
	    mail_free_searchpgm (&pgm);
	    break;
	}
    }
    return pgm;
}

/*
 * Mail parse search criteria for logical NOT or OR
 * Accepts: criteria
 * Returns: search program if parse successful, else NIL
 */

SEARCHPGM *make_criteria(char *criteria)
{
    int i = 0;
    char string_not[CRITERIATMPLEN] = "";
    char string_or[2][CRITERIATMPLEN] = {"",""};
    char string[CRITERIATMPLEN] = "";
    short crit = 0;
    short orcrit = 0;
    short notcrit = 0;
    short n = 0;
    short group = 0;
    short quot = 0;
    char tmp[MAILTMPLEN] = "";
    SEARCHPGM *spgm;

    if(!criteria) return NIL;
    while(*criteria) {
	if(*(criteria-1) != '\\' && *criteria == '"') quot = (quot) ? 0 : 1;
	if(*criteria == '(') group = 1;
	if(notcrit) {
	    if(!group && !quot && *criteria == ' ' && *(criteria+1) != '"') {
		notcrit = 0;
		i = 0;
	    } else if(*criteria != '(' && *criteria != ')')
		string_not[i++] = *criteria;
	}
	if(!notcrit && !group && !quot &&
		((*criteria == ' ' && n) || !n) &&
		*(criteria+n) == 'N' &&
		*(criteria+n+1) == 'O' &&
		*(criteria+n+2) == 'T' &&
		*(criteria+n+3) == ' ') {
	    criteria = criteria + n + 3;
	    notcrit = 1;
	    orcrit = 0;
	    i = 0;
	}
	if(orcrit) {
	    if(!group && !quot && *criteria == ' ' && *(criteria+1) != '"') {
		i = 0;
		crit++;
	    }
	    if(crit > 1) {
		orcrit = 0;
		i = 0;
	    } else if((*criteria != ' ' || i) &&
			(*criteria != '(' && *criteria != ')'))
		string_or[crit][i++] = *criteria;
	}
	if(!orcrit && !group && !quot &&
		((*criteria == ' ' && n) || !n) &&
		*(criteria+n) == 'O' &&
		*(criteria+n+1) == 'R' &&
		*(criteria+n+2) == ' ') {
	    criteria = criteria + n + 2;
	    notcrit = 0;
	    orcrit = 1;
	    i = 0;
	}
	if(!notcrit && !orcrit && (*criteria != ' ' || i))
	    string[i++] = *criteria;
	++criteria;
	if(*criteria == ')') group = 0;
	n = 1;
    }
    if(group || quot) {
	sprintf (tmp,"criteria miss: '\"' or ')'");
	MM_LOG (tmp,ERROR);
	return NIL;
    }
    spgm = mail_newsearchpgm();
    if(string[0]) spgm = _mail_criteria(string);
    if(string_not[0]) {
	spgm->not = mail_newsearchpgmlist();
	spgm->not->pgm = _mail_criteria(string_not);
    }
    if(string_or[0][0] && string_or[1][0]) {
	spgm->or = mail_newsearchor();
	spgm->or->first = _mail_criteria(string_or[0]);
	spgm->or->second = _mail_criteria(string_or[1]);
    }
    return spgm;
}
