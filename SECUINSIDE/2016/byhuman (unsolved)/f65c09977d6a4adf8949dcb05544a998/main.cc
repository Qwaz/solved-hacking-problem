#include "common.h"

using namespace std;

bool writebuffer(const char *c, int length) {
	RANDOM;
	if(write(1, &length, sizeof(length)) != sizeof(length)) return false;
	if(write(1, c, length) != length) return false;
	return true;
}

bool writestr(const char *c) {
	RANDOM;
	int length = string_length(c);
	return writebuffer(c, length);
}

bool readbytes(void *c, int len) {
	RANDOM;
	char *ptr = (char *)c;
	int remain = len;
	int offset = 0;
	while(remain > 0) {
		int result = read(0, ptr + offset, remain);
		if(result <= 0) return false;
		remain -= result;
		offset += result;
	}
	return true;
}

bool readbuffer(char *&c, int &length) {
	RANDOM;
	char *buffer;
	int length_;
	if(!readbytes(&length_, sizeof(length_))) return false;
	length = length_;
	if(length < 0 || length > 0x1000000) return false;
	buffer = new char[length_];
	if(buffer == NULL) return false;
	if(!readbytes(buffer, length)) return false;
	c = buffer;
	return true;
}

int main() {
	RANDOM;
	bool isEnded = false;
	char *pickle = NULL;
	int length = 0;
	writestr("Pickle Shell made by human\n");
	writestr("If you found any vulnerability, use it for your own cyber weapon.\n");
	writestr("Isn't it cool? Admit? B: Yes, I admit.\n");

	while(!isEnded) {
		std::string *result;
		Item *resultItem;
		isEnded = !readbuffer(pickle, length);
		if(isEnded) _exit(0);
		resultItem = eval(pickle, length);
		if(resultItem) {
			if(resultItem->type != VAR_STRING)
				result = resultItem->toString()->toCString();
			else
				result = static_cast<String *>(resultItem)->toCString();
		}
		else
			_exit(0);
		writebuffer(result->c_str(), result->size());
	}
	_exit(0);
	return 0;
}