#ifndef _IDEA_DEFINED

#define _IDEA_DEFINED

#include "windows.h"
#include "iostream"
using namespace std;

#define word16	unsigned short int
#define word32	unsigned long int

#define burn(x)	memset( x, 0, sizeof( x ) )

/* Константы алгоритма */

#define IDEAKEYSIZE		16
#define IDEABLOCKSIZE	8

#define IDEAROUNDS		8
#define IDEAKEYLEN		( 6 * IDEAROUNDS + 4 )

/* Процедуры, используемые в алгоритме */
void ideaExpandKey( byte const *userkey, word16 *EK );

#ifdef _DCC
void ideaInvertKey( word16 *EK, word16 DK[IDEAKEYLEN] );
void ideaCipher( byte (inbuf[8]), byte (outbuf[8]), word16 *key );
#else
void ideaInvertKey( word16 const *EK, word16 DK[IDEAKEYLEN] );
void ideaCipher( byte const (inbuf[8]), byte (outbuf[8]), word16 const *key );
#endif

#endif
