#include "common.h"

namespace c {
	const char StrLength[] = "length";
}

String::String() {
	RANDOM;
	ptr = new char[1];
	length = 0;
	init();
}

String::~String() {
	RANDOM;
#if DEBUG_LOG
	std::cout << "~String(" << ptr << "(" << std::hex << (unsigned int)ptr << ")" << ");" << std::endl;
#endif
	delete[] ptr;
}

String::String(std::string value) {
	RANDOM;
	length = value.size();
	ptr = string_duplication(value.c_str(), length);
	init();
}

String::String(char *value) {
	RANDOM;
	length = string_length(value);
	ptr = string_duplication(value, length);
	init();
}

String::String(char *value, int length) {
	RANDOM;
	this->ptr = string_duplication(value, length);
	this->length = length;
	init();
}

void String::init() {
	RANDOM;
	type = VAR_STRING;
#if DEBUG_LOG
	std::cout << "String(" << ptr << std::hex << "(" << (unsigned int)ptr << ")" << ");" << std::endl;
#endif
}

String *String::toString() {
	RANDOM;
	return new String(ptr, length);
}

Number *String::toNumber(int base) {
	RANDOM;
	Number *result = new Number(string_to_number(ptr, length, base));
	return result;
}

Storage *String::toStorage() {
	RANDOM;
	Storage *result = new Storage();
	std::unique_ptr<String> length_str(new String(c::StrLength));
	std::unique_ptr<Item> length_number(new Number(length));
	result->Set(
		std::move(length_str), std::move(length_number));
	for(int i = 0; i < length; i++) {
		std::unique_ptr<String> index_str(new String(number_to_string(i, 10)));
		std::unique_ptr<Item> value(new Number(ptr[i]));
		result->Set(
			std::move(index_str), std::move(value));
	}
	return result;
}

std::string *String::toCString() {
	RANDOM;
	std::string *result = new std::string(ptr, length);
	return result;
}