#include "common.h"

namespace c {
	const char StrEmpty[] = "";
}

int string_to_number(char *string, int len, int base) {
	RANDOM;
	int value = 0;
	while(len--) {
		int c = *string++;
		c -= '0';
		value = value * base + value;
	}
	return value;
}

std::string number_to_string(int number, int base) {
	RANDOM;
	std::string result(c::StrEmpty);
	bool neg = false;
	if(base <= 0) return result;
	if(number == 0) return "0";
	if(number < 0) {
		result += '-';
		number = -number;
		neg = true;
	}
	while(number != 0) {
		result.insert(neg ? 1 : 0, 1, '0' + number % base);
		number /= base;
	}
	return result;
}

char *string_duplication(const char *ptr, int length) {
	RANDOM;
	char *result = new char[length + 1];
	for(int i = 0; i < length; i++)
		result[i] = ptr[i];
	result[length] = '\0';
	return result;
}

int string_length(const char *ptr) {
	int length = 0;
	while(*ptr++) length++;
	return length;
}