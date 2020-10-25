#define _CRT_SECURE_NO_WARNINGS


#include <string.h>
#include <conio.h>

#ifdef _MSC_VER
   #include "idea.h"
#else
  #include "idea/idea.h"
#endif /* _MSC_VER */

#ifdef BIG_ENDIAN		
  #define HIGHFIRST
#endif /* BIG_ENDIAN */

#ifdef IDEA32	/* 16-разрядные переменные */
#define low16(x) ((x) & 0xFFFF)
typedef unsigned int uint16;	/* 16 бит или больше */
#else
#define low16(x) (x)
typedef word16 uint16;
#endif

#ifdef SMALL_CACHE
CONST static uint16
mul(register uint16 a, register uint16 b)
{
	register word32 p;

	p = (word32)a * b;
	if (p) {
		b = low16(p);
		a = p>>16;
		return (b - a) + (b < a);
	} else if (a) {
		return 1-b;
	} else {
		return 1-a;
	}
} /* mul */
#endif /* малый кэш */


CONST static uint16
//Инвертирование числа
mulInv(uint16 x)     
{
	uint16 t0, t1;
	uint16 q, y;

	if (x <= 1)
		return x;	
	t1 = 0x10001L / x;	
	y = 0x10001L % x;
	if (y == 1)
		return ( uint16 ) low16(1-t1);
	t0 = 1;
	do {
		q = x / y;
		x = x % y;
		t0 += q * t1;
		if (x == 1)
			return t0;
		q = y / x;
		y = y % x;
		t1 += q * t0;
	} while (y != 1);
	return ( uint16 ) low16(1-t1);
}

//Расширение пользовательского ключа до ключа шифрования
void ideaExpandKey(byte const *userkey, word16 *EK)
{
	int i,j;
	//Формируем начальные 8 байт ключа
	for (j=0; j<8; j++) {
		EK[j] = (userkey[0]<<8) + userkey[1];
		userkey += 2;
	}
	//Генериируем все 52 подключа
	for (i=0; j < IDEAKEYLEN; j++) {
		i++;
		EK[i+7] = (EK[i & 7] << 9) | (EK[i+1 & 7] >> 7);
		EK += i & 8;
		i &= 7;
	}
} /* ideaExpandKey */

/*
 Вычисление ключа дешифрации
 */
void
#ifdef _DCC
ideaInvertKey(word16 *EK, word16 DK[IDEAKEYLEN])
#else
ideaInvertKey(word16 const *EK, word16 DK[IDEAKEYLEN])
#endif
{
	int i;
	uint16 t1, t2, t3;
	word16 temp[IDEAKEYLEN];
	word16 *p = temp + IDEAKEYLEN;


	t1 = mulInv(*EK++);
	t2 = - ( int ) *EK++;
	t3 = - ( int ) *EK++;
	*--p = mulInv(*EK++);
	*--p = t3;
	*--p = t2;
	*--p = t1;

	for (i = 0; i < IDEAROUNDS-1; i++) {
		t1 = *EK++;
		*--p = *EK++;
		*--p = t1;

		t1 = mulInv(*EK++);
		t2 = - ( int ) *EK++;
		t3 = - ( int ) *EK++;
		*--p = mulInv(*EK++);
		*--p = t2;
		*--p = t3;
		*--p = t1;
	}
	t1 = *EK++;
	*--p = *EK++;
	*--p = t1;

	t1 = mulInv(*EK++);
	t2 = - ( int ) *EK++;
	t3 = - ( int ) *EK++;
	*--p = mulInv(*EK++);
	*--p = t3;
	*--p = t2;
	*--p = t1;
/* Создаем ключ и уничтожаем временную копию */
	memcpy(DK, temp, sizeof(temp));
	burn(temp);
} /* ideaInvertKey */

/*
Вычисляет x = x*y, в побитовых операциях, mod 0x10001
 */
#ifdef SMALL_CACHE
#define MUL(x,y) (x = mul(low16(x),y))
#else /* !SMALL_CACHE */
#ifdef AVOID_JUMPS
#define MUL(x,y) (x = low16(x-1), t16 = low16((y)-1), \
		t32 = (word32)x*t16 + x + t16 + 1, x = low16(t32), \
		t16 = t32>>16, x = (x-t16) + (x<t16) )
#else /* !AVOID_JUMPS (default) */
#define MUL(x,y) \
	((t16 = (y)) ? \
		(x=low16(x)) ? \
			t32 = (word32)x*t16, \
			x = low16(t32), \
			t16 = t32>>16, \
			x = (x-t16)+(x<t16) \
		: \
			(x = 1-t16) \
	: \
		(x = 1-x))
#endif
#endif

/*	Алгоритм шифрования и дешифрования IDEA */
/* Note that in and out can be the same buffer */
void
#ifdef _DCC
ideaCipher(byte (inbuf[8]), byte (outbuf[8]), word16 *key)
#else
ideaCipher(byte const (inbuf[8]), byte (outbuf[8]), word16 const *key)
#endif
{
	register uint16 x1, x2, x3, x4, s2, s3;
	word16 *in, *out;
#ifndef SMALL_CACHE
	register uint16 t16;	/* Temporaries needed by MUL macro */
	register word32 t32;
#endif
	int r = IDEAROUNDS;

	in = (word16 *)inbuf;
	x1 = *in++;  x2 = *in++;
	x3 = *in++;  x4 = *in;
#ifndef HIGHFIRST
	x1 = (x1>>8) | (x1<<8);
	x2 = (x2>>8) | (x2<<8);
	x3 = (x3>>8) | (x3<<8);
	x4 = (x4>>8) | (x4<<8);
#endif
	do {
		MUL(x1,*key++);
		x2 += *key++;
		x3 += *key++;
		MUL(x4, *key++);

		s3 = x3;
		x3 ^= x1;
		MUL(x3, *key++);
		s2 = x2;
		x2 ^= x4;
		x2 += x3;
		MUL(x2, *key++);
		x3 += x2;

		x1 ^= x2;  x4 ^= x3;

		x2 ^= s3;  x3 ^= s2;
	} while (--r);
	MUL(x1, *key++);
	x3 += *key++;
	x2 += *key++;
	MUL(x4, *key);

	out = (word16 *)outbuf;
#ifdef HIGHFIRST
	*out++ = x1;
	*out++ = x3;
	*out++ = x2;
	*out = x4;
#else /* !HIGHFIRST */
	x1 = low16(x1);
	x2 = low16(x2);
	x3 = low16(x3);
	x4 = low16(x4);
	*out++ = (x1>>8) | (x1<<8);
	*out++ = (x3>>8) | (x3<<8);
	*out++ = (x2>>8) | (x2<<8);
	*out   = (x4>>8) | (x4<<8);
#endif
} /* ideaCipher */

/*-------------------------------------------------------------*/


#include <stdio.h>
#include <time.h>
#include <string.h>
#ifndef BLOCKS
#ifndef KBYTES
#define KBYTES 1024
#endif
#define BLOCKS (64*KBYTES)
#endif

using namespace std;
#include <iostream>
#include <fstream>
#include <conio.h>
#include "locale.h"

bool encryptAll()
{
	int i, j, k;
	//Пользовательские ключи
	byte userkey[16];
	byte userkey2[16];
	//Ключ шифрования 1
	word16 EK[IDEAKEYLEN];
	//Ключ расшифровки 1
	word16 DK[IDEAKEYLEN];
	//Ключ шифрования 2
	word16 EK2[IDEAKEYLEN];
	//Ключ расшифровки 2
	word16 DK2[IDEAKEYLEN];

	//Шифруемый текст, шифр, расшифрованный текст
	byte bArray[8], YY[8], ZZ[8];
	//Время начала и завершения операции
	clock_t start, end;
	long l;

	//Обнуляем значения ключей
	for(int i=0;i<16;i++){
		userkey[i]=0;
		userkey2[i]=0;
	}
	//Файл ключей
	FILE * file_userkey;
	char * fukey_name = "keys.txt";
	//Открываем файл для чтения
	file_userkey = fopen(fukey_name,"r");
	//Проверяем наличие файла
	if(file_userkey ==0){
		printf("Невозможно открыть файл '%s'!",fukey_name);
		getch();
		return 0;
	}
	//строка для считывания ключа
	char key_string[256];
	//признак переключения на ключ 2
	bool b = false;
	//признак наполнения ключа 1
	bool bKey1Entered = false;
	//признак наполнения ключа 2
	bool bKey2Entered = false;
	//Считываем значения ключа
	while(fgets(key_string,sizeof(key_string),file_userkey))
	{
		int ii = 0;
		for(int i=0;i<16;i++){
			//Новая строка отделямт ключи
			if(key_string[i]=='\n'){
				b = true;
			}
			else{
				//наполняем 1 ключ
				if(!b){
					userkey[ii] = key_string[i];
					ii++;
					if(ii==16){
						ii=0;
						b = true;
					}
					bKey2Entered = true;
				}//наполняем 2-й ключ
				else{
					bKey1Entered = true;
					userkey2[ii] = key_string[i];
					ii++;
					if(ii==16)break;
				}				
			}
		}
	}
	//один из ключей заполнен некорректно
	if(!(bKey1Entered && bKey2Entered))
	{
		printf("'Ошибка чтения ключа '%s'!",fukey_name);
		getch();
		return 0;
	}
	fclose(file_userkey);


	/* Вычисляем подключи из пользовательского ключа... */
	ideaExpandKey(userkey, EK);
	ideaExpandKey(userkey2, EK2);
	
	//Получаем код расшифровки
	ideaInvertKey(EK, DK);
	ideaInvertKey(EK2,DK2);

	//открываем файл для записи
 	FILE *file_w; 
 	char *fname_w = "output.txt";
 	//char *fname_w = "input.txt";
 	file_w = fopen(fname_w,"wb");
 	if(file_w==0){
 		printf("Невозможно создать файл вывода шифровки '%s'!",fname_w);
 		getch();
 		return 0;
 	}

	//открываем файл расшифровки для записи
	FILE *file_decryptw; 
	char *fname_decryptw = "output_decrypt.txt";
	file_decryptw = fopen(fname_decryptw,"wb");
	if(file_decryptw==0){
		printf("Невозможно создать файл дешифрованного текста '%s'!",fname_decryptw);
		getch();
		return 0;
	}

	//открываем файл с бинарной шифровкой
	FILE *file_binw; 
	char *fname_binw = "output_binary.bin";
	file_binw = fopen(fname_binw,"wb");
	if(file_binw==0){
		printf("Невозможно создать бинарный файл шифровки '%s'!",fname_binw);
		getch();
		return 0;
	}

	//открываем файл с исходным текстом
	FILE *file; 
	char *fname = "input.txt";
	//char *fname = "output.txt";
	char result_sting[8]; //Строка в 8 символов
	file = fopen(fname,"rb");
	if(file == 0)
	{
		printf("Невозможно открыть файл '%s'!",fname);
		getch();
		return 0;
	}
	while(fgets(result_sting,sizeof(result_sting),file))
	{
		//byte bArray[8];
		for(int i=0;i<8;i++){
			if(i<strlen(result_sting)+1)
				bArray[i] = result_sting[i];
			else
				bArray[i] = 0;
		}

		fflush(stdout);
		//Запоминаем текущий момент времени
		start = clock();
		//Копируем в массив YY значения из bArray
		memcpy(YY, bArray, 8);
		//Шифруем текст прямым ключом 1
		for (l = 0; l < BLOCKS; l++)
			ideaCipher(YY, YY, EK);
		//-------------------------------------------------------------------------//
		//Дешифруем текст обратным ключом 2
		for (l = 0; l < BLOCKS; l++)
			ideaCipher(YY, YY, DK2);
		//Шифруем текст прямым ключом 1
		for (l = 0; l < BLOCKS; l++)
			ideaCipher(YY, YY, EK);
		//-------------------------------------------------------------------------//
		memcpy(ZZ, YY, 8);
		//Дешифруем текст обратным ключом 1
		for (l = 0; l < BLOCKS; l++)
			ideaCipher(ZZ, ZZ, DK);	
		//Шифруем текст прямым ключом 2
		for (l = 0; l < BLOCKS; l++)
			ideaCipher(ZZ, ZZ, EK2);
		//Дешифруем текст обратным ключом 1
		for (l = 0; l < BLOCKS; l++)
			ideaCipher(ZZ, ZZ, DK);
		//-------------------------------------------------------------------------//

		//Вычисляем время, затраченное на выполнение операций
		end = clock() - start;
		//переводим время в миллисекунды
		l = end  / (CLOCKS_PER_SEC/1000) + 1;
		i = l/1000;
		j = l%1000;

		/* Проверяем корректность дешифрации */
		for (k=0; k<8; k++)
			if (bArray[k] != ZZ[k]) {
				printf("\n\07Ошибка! Некорректная расшифровка.\n");
				getch();
				fclose(file);
				fclose(file_w);
				exit(-1);	/* error exit */ 
			}
			//Выводим шифровку в файл
 			char sCrypted[8];
 			memset(&sCrypted,0,sizeof(sCrypted));
 			char sDecrypted[8];
 			for(int i=0;i<8;i++){
 				sCrypted[i] = YY[i];
 				sDecrypted[i] = ZZ[i];	
 			}
 			fputs(sCrypted,file_w);
 			fputs(sDecrypted,file_decryptw);
			fwrite(YY,1,sizeof(YY),file_binw);
	}
	//Закрываем все файлы
	fclose(file);
	fclose(file_w);
	fclose(file_decryptw);
	fclose(file_binw);
	return true;
}


//Функция дешифрации содержимого бинарного файла
bool decryptAll()
{
	int i, j, k;
	//Пользовательские ключи
	byte userkey[16];
	byte userkey2[16];
	//Ключ шифрования 1
	word16 EK[IDEAKEYLEN];
	//Ключ расшифровки 1
	word16 DK[IDEAKEYLEN];
	//Ключ шифрования 2
	word16 EK2[IDEAKEYLEN];
	//Ключ расшифровки 2
	word16 DK2[IDEAKEYLEN];

	//Шифруемый текст, шифр, расшифрованный текст
	byte bArray[8], YY[8], ZZ[8];
	//Время начала и завершения операции
	clock_t start, end;
	long l;

	//Обнуляем значения ключей
	for(int i=0;i<16;i++){
		userkey[i]=0;
		userkey2[i]=0;
	}
	//Файл ключей
	FILE * file_userkey;
	char * fukey_name = "keys.txt";
	//Открываем файл для чтения
	file_userkey = fopen(fukey_name,"r");
	//Проверяем наличие файла
	if(file_userkey ==0){
		printf("Can't open the file '%s'!",fukey_name);
		getch();
		return 0;
	}
	//строка для считывания ключа
	char key_string[256];
	//признак переключения на ключ 2
	bool b = false;
	//признак наполнения ключа 1
	bool bKey1Entered = false;
	//признак наполнения ключа 2
	bool bKey2Entered = false;
	//Считываем значения ключа
	while(fgets(key_string,sizeof(key_string),file_userkey))
	{
		int ii = 0;
		for(int i=0;i<16;i++){
			//Новая строка отделямт ключи
			if(key_string[i]=='\n'){
				b = true;
			}
			else{
				//наполняем 1 ключ
				if(!b){
					userkey[ii] = key_string[i];
					ii++;
					if(ii==16){
						ii=0;
						b = true;
					}
					bKey2Entered = true;
				}//наполняем 2-й ключ
				else{
					bKey1Entered = true;
					userkey2[ii] = key_string[i];
					ii++;
					if(ii==16)break;
				}				
			}
		}
	}
	//оодин из ключей заполнен некорректно
	if(!(bKey1Entered && bKey2Entered))
	{
		printf("'Ошибка чтения ключа '%s'!",fukey_name);
		getch();
		return 0;
	}
	fclose(file_userkey);


	/* Вычисляем подключи из пользовательского ключа... */
	ideaExpandKey(userkey, EK);
	
	//Получаем код расшифровки
	ideaInvertKey(EK, DK);
	ideaInvertKey(EK2,DK2);
	
	//открываем файл для записи
	FILE *file_w; 
	char *fname_w = "output.txt";
	//char *fname_w = "input.txt";
	file_w = fopen(fname_w,"wb");
	if(file_w==0){
		printf("Невозможно создать файл вывода шифровки '%s'!",fname_w);
		getch();
		return 0;
	}

	//открываем файл с бинарной шифровкой
	FILE *file; 
	char *fname = "output_binary.bin";
	//char *fname = "output.txt";
	char result_sting[8]; //Строка в 8 символов
	file = fopen(fname,"rb");
	if(file == 0)
	{
		printf("Невозможно открыть файл '%s'!",fname);
		getch();
		return false;
	}
	//Перемещаем указатель на начало
	fseek (file , 0 , SEEK_END);
	//Определяем размер файла
	long lSize = ftell (file);
	rewind (file);

	// выделяем память для считывания всего файла
	char * buffer = (char*) malloc (sizeof(char)*lSize);
	if (buffer == NULL) {fputs ("Ошибка памяти",stderr); exit (2);}

	// копируем файл в буфер
	size_t result = fread (buffer,1,lSize,file);
	if (result != lSize) {fputs ("Ошибка чтения",stderr); exit (3);}

	i=0;
	int leng = 0;
	while (1){
	/*while (leng<=lSize){*/
		//заполняем блоки по 8 байт
		if(i==0){
			for(int j=0;j<8;j++){
				if(leng<lSize)
				{
					bArray[j] = buffer[leng];
					leng++;
				}	
				else
				bArray[j] = 0;
			}
			i=1;
		}
		//Осуществляем дешифрацию
		else{
			fflush(stdout);
			//Запоминаем текущий момент времени
			start = clock();
			//Копируем в массив YY значения из bArray
			memcpy(ZZ, bArray, 8);
			//Дешифруем текст обратным ключом 1
			for (l = 0; l < BLOCKS; l++)
				ideaCipher(ZZ, ZZ, DK);	
			//Шифруем текст прямым ключом 2
			for (l = 0; l < BLOCKS; l++)
				ideaCipher(ZZ, ZZ, EK2);
			//Дешифруем текст обратным ключом 1
			for (l = 0; l < BLOCKS; l++)
				ideaCipher(ZZ, ZZ, DK);
			//-------------------------------------------------------------------------//

			//Вычисляем время, затраченное на выполнение операций
			end = clock() - start;
			//переводим время в миллисекунды
			l = end  / (CLOCKS_PER_SEC/1000) + 1;
			i = l/1000;
			j = l%1000;
			

				//Выводим дешифрованный блок в файл
				char sDecrypted[8];
				for(int i=0;i<8;i++){
					sDecrypted[i] = ZZ[i];	
				}
				fputs(sDecrypted,file_w);				
			i=0;
		}
		if ((leng>=lSize) && (i==0))
			break;
		//i=0;
	}

	fclose(file);
	fclose(file_w);
	printf("\n\nРезультат дешифрации находится в файле output.txt\n");

	return true;
}

int main(void)
{	
	//Устанавливаем локаль для русского языка
	setlocale(LC_ALL,"Rus");
	printf("Программа трехкратного шифрования и дешифрации трехключевого IDEA методом EDE.\n"); 
	printf("Исходные данные: \n"); 
	printf("1)Файл ключей (keys.txt). В данный файл заносятся 2 ключа шифрации, разделенные знаком переноса строки\n"); 
	printf("2)Файл исходного текста для шифровки. В данный файл необходимо занести шифруемый текст\n"); 
	printf("3)Бинарный файл - шифр(output-binary), который содержит бинарное представление \nуже зашифрованного ранее текста\n"); 
	printf("Программа работает в двух режимах:\n"); 
	printf("1) Режим шифрации. При этом исходный текст берется из файла input.txt, шифруется.\n"); 
	printf("   Шифр выводится в бинарном виде в файл output-binary. Расшифрованный текст\n(для проверки) выводится в файл output_decrypt.txt\n");
	printf("2) Режим дешифрации. При этом считывается содержимое файла output - binary, \nи расшифровка выводится в файл output.\n"); 
	printf("\n");
	char ch=' ';
	//Выбираем режим работы программы
	while(!(ch == 'd' || ch=='D'||ch=='e'||ch=='E'||ch=='у'||ch=='У'||ch=='в'||ch=='В')){
		printf("Режим шифрации - 'e', режим дешифрации - 'd'");
		cin >> ch;
		if(ch=='d'||ch=='D'||ch=='в'||ch=='В'){
			//		
			if(!decryptAll()){
				printf("Критическая ошибка при дешифрации!");
				getch();
				exit(-1);
			}
		}
		else 
			if(ch=='e'||ch=='E'||ch=='у'||ch=='У'){
				if(!encryptAll()){
					printf("Критическая ошибка при шифрации!");
					getch();
					exit(-1);
				}
			}
			else{
				printf("Вы ввели неверный символ!\n");
			}
	}
	printf("\n\nВсе операции успешно завершены!");
	//Задерживаем консоль
	getch();
	return 0;	
} 

