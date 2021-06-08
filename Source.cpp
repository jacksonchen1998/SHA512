///SHA-512/
#include "stdafx.h"
#include <iostream>
#include <fstream>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctime>

#define MUL_BYTES 1024
#define MUL_KB (MUL_BYTES*1024)
#define MUL_MB (MUL_KB*1024)

using namespace std;
unsigned long long datas[0x2000000];//load 起始資料、
unsigned long long T1, T2, W[80];//當前使用的訊息，和每輪中保存的消息
unsigned long long HashI_1[8];//中間部分结果
unsigned long long HashI[8];//最终輸出结果
unsigned long long byte_size = 0;
char output[20000000];


const unsigned long long Kt[80] = {//constant
		0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
		0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
		0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
		0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
		0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
		0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
		0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
		0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
		0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
		0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
		0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
		0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
		0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
		0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
		0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
		0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
		0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
		0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
		0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
		0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
		0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
		0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
		0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
		0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
		0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
		0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
		0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

void InitializeHash() {//初始化 HashI_1 HashI
	HashI[0] = 0x6a09e667f3bcc908;
	HashI[1] = 0xbb67ae8584caa73b;
	HashI[2] = 0x3c6ef372fe94f82b;
	HashI[3] = 0xa54ff53a5f1d36f1;
	HashI[4] = 0x510e527fade682d1;
	HashI[5] = 0x9b05688c2b3e6c1f;
	HashI[6] = 0x1f83d9abfb41bd6b;
	HashI[7] = 0x5be0cd19137e2179;
}
unsigned long long ROTR(unsigned long long x, int n){
	return ((x >> n) | (x << (64 - n)));//循環右移n
}
void SHA_512(int N) {
	int i, t, j;
	for (i = 0; i < N;i++) {
		for (j = 0; j < 16;j++) {
			W[j] = datas[i * 16 + j];//由全部資料中载入本次所需的訊息
		}	
		for (j = 16;j < 80;j++) {//計算出第16-79輪的訊息
			W[j] = (ROTR(W[j - 2], 19) ^ ROTR(W[j - 2], 61) ^ (W[j - 2] >> 6)) + W[j - 7] + (ROTR(W[j - 15], 1) ^ ROTR(W[j - 15], 8) ^ (W[j - 15] >> 7)) + W[j - 16];
		}
		for (j = 0;j < 8;j++)
			HashI_1[j] = HashI[j];//當每次输入開始之前，將之前得到的输出load進去，之後對中間的hashI_1值進行操作，输出给HashI
		for (t = 0;t < 80;t++) {//第80輪操作
			T1 = HashI_1[7] + ((HashI_1[4] & HashI_1[5]) ^ ((~HashI_1[4]) & HashI_1[6]))
				+ (ROTR(HashI_1[4], 14) ^ ROTR(HashI_1[4], 18) ^ ROTR(HashI_1[4], 41)) + W[t] + Kt[t];
			T2 = (ROTR(HashI_1[0], 28) ^ ROTR(HashI_1[0], 34) ^ ROTR(HashI_1[0], 39))
				+ ((HashI_1[0] & HashI_1[1]) ^ (HashI_1[0] & HashI_1[2]) ^ (HashI_1[1] & HashI_1[2]));

			HashI_1[7] = HashI_1[6];
			HashI_1[6] = HashI_1[5];
			HashI_1[5] = HashI_1[4];
			HashI_1[4] = HashI_1[3] + T1;
			HashI_1[3] = HashI_1[2];
			HashI_1[2] = HashI_1[1];
			HashI_1[1] = HashI_1[0];
			HashI_1[0] = T1 + T2;

			cout << "-------------------" << "Round" << t + 1 << "-------------------\n";
			for (j = 0;j < 8;j++) {
				cout << HashI_1[j] << "\n";
				byte_size += sizeof(HashI_1[i]);
			}
		}
		for (j = 0;j < 8;j++)
			HashI[j] += HashI_1[j];//得到输出
	}
}

int main() {
	int i, t, k, l, j = 0, NUM_CYCLE = 1000000;
	int N, M;//總共n個1024,M個256m
	unsigned char lastChar[128];
	unsigned long long TxtLength;
	string in_filename, out_filename;
	clock_t start = 0, end = 0;
	double time;

	FILE* fp;
	errno_t erro;
	InitializeHash();

	cout << "Input file's path : ";
	cin >> in_filename;//指定讀取檔案路徑
	cout << "Output file's path : ";
	cin >> out_filename;//指定寫入檔案路徑

	start = clock();

	const char* out = out_filename.c_str();

	fstream datasf(in_filename, ios::in | ios::binary);
	
	erro = fopen_s(&fp, out, "w+");

	datasf.seekp(0, ios::end);
	TxtLength = datasf.tellp();//得到檔案文字大小
	datasf.seekp(0, ios::beg);
	N = 1 << 21;//256m中 含有 1^21個的1024
	M = (TxtLength >> 28) + 1;//得到資料有多少個256m的區塊
	for (t = 0; t < M;t++) {
		if (t == M - 1) {
			N = (TxtLength - (1 << 28) * (M - 1)) >> 7;//當只剩下最後一组256m時，計算剩下的1024组数-1
			for (i = 0;i < N;i++) {//將剩下的1024的组先load進來
				datasf.read((char*)lastChar, 128);//一次讀取128個char
				for (k = 0;k < 16;k++) {
					datas[j] = 0;
					for (l = 0;l < 8;l++)
						datas[j] = (datas[j] << 8) | lastChar[k * 8 + l];
					j++;
				}
			}
			N = TxtLength - (1 << 28) * (M - 1) - (N << 7);//計算最後剩下的字節數為和
			for (i = 0;i < N;i++)
				datasf.read((char*)(&lastChar[i]), 1);
			if (i >= 112) {//補餘時，若最後一段大於896則必须再加一層1024.
				lastChar[i++] = 128;//最高位填充1之後填補0 
				for (;i < 128;i++)
					lastChar[i] = 0;
				for (i = 0;i < 16;i++) {
					datas[j] = 0;
					for (k = 0;k < 8;k++)
						datas[j] = (datas[j] << 8) | lastChar[i * 8 + k];
					j++;
				}
				for (i = 0;i < 112;i++)//新的1024行要再次填補到896位
					lastChar[i] = 0;
			}
			else {
				lastChar[i++] = 128;//最高位填補1之后填補0 
				for (;i < 112;i++)
					lastChar[i] = 0;
			}
			//最後128位是訊息長度，第一個數固定為0，第二個數直接為TextLength * 8
			//将資料從lastChar字组中load到datas数组中
			for (i = 0;i < 14;i++) {
				datas[j] = 0;
				for (k = 0;k < 8;k++)
					datas[j] = (datas[j] << 8) | lastChar[i * 8 + k];
				j++;
			}
			datas[j++] = 0;
			datas[j++] = TxtLength << 3;
			N = j >> 4;//j的數量肯定是合理的，则可以由此時j的數量得到最後1024的字数
			SHA_512(N);//進行hash function
		}
		else {
			for (i = 0;i < N;i++) {
				datasf.read((char*)lastChar, 128);
				for (k = 0;k < 16;k++) {
					datas[j] = 0;
					for (l = 0;l < 8;l++)
						datas[j] = (datas[j] << 8) | lastChar[k * 8 + l];
					j++;
				}
			}
			SHA_512(N);//
		}
	}
	datasf.close();
	end = clock();
	time = (double)(end - start)/CLOCKS_PER_SEC;
	cout << "-------------------------------------\n";
	cout << "SHA-512 Transfermission complete " << endl;
	for (j = 0; j < 8;j++) {
		fprintf(fp, "%016I64x\n", HashI[j]);//輸入到指定txt file中
		byte_size += HashI[j]; 
	}
	cout << "Spend time : "<< byte_size / time<< " bytes/second \n";//輸出運算bytes per second
	fclose(fp);
	cin >> lastChar[0];
	return 0;
}
