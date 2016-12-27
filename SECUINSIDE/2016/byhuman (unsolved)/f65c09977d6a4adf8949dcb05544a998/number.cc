#include "common.h"

Number::Number(int value) {
	RANDOM;
	this->type = VAR_NUMBER;
	this->value = value;
#if DEBUG_LOG
	std::cout << "Number(" << std::dec << value << ");" << std::endl;
#endif
}

Number::~Number() {
	RANDOM;
#if DEBUG_LOG
	std::cout << "~" << "Number(" << std::dec << value << ");" << std::endl;
#endif
}

Number *Number::toNumber(int base) {
	RANDOM;
	return new Number(value);
}

String *Number::toString() {
	RANDOM;
	std::string result_str = number_to_string(value, 10);
	String *result = new String(result_str);
	return result;
}

Storage *Number::toStorage() {
	RANDOM;
	return NULL;
}

void Number::Add(Number *b) {
	RANDOM;
	value += b->value;
}

int Number::Get() {
	RANDOM;
	return value;
}