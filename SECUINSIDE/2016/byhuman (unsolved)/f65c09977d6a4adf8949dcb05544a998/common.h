#ifndef __COMMON_H__
#define __COMMON_H__

#include "std.h"

int string_to_number(char *, int, int);
std::string number_to_string(int, int);
char *string_duplication(const char *ptr, int length);
int string_length(const char *ptr);

class Storage;
class String;
class Number;
class Item;

typedef std::unique_ptr<Item> ItemPtr;

enum VarType {
	VAR_ITEM = 0,
	VAR_NUMBER,
	VAR_STRING,
	VAR_STORAGE
};

Item *eval(const char *code, int length);

class Item {
public:
	Item();
	virtual ~Item();
	virtual String *toString();
	virtual Number *toNumber(int base=10);
	virtual Storage *toStorage();
	int type;
};

class Storage : public Item {
public:
	Storage();
	virtual ~Storage();
	bool Set(ItemPtr key, ItemPtr value);
	Item *Get(ItemPtr key);
	virtual String *toString() override;
	virtual Number *toNumber(int base=10) override;
	virtual Storage *toStorage() override;
private:
	std::map<ItemPtr, ItemPtr> items;
	int state;
};

class String : public Item {
public:
	String(std::string value);
	String(char *value);
	String(char *value, int length);
	String();
	virtual ~String();
	std::string *toCString();
	virtual String *toString() override;
	virtual Number *toNumber(int base) override;
	virtual Storage *toStorage() override;
private:
	void init();
	char *ptr;
	int length;
};

class Number : public Item {
public:
	Number(int number);
	Number();
	virtual ~Number();
	virtual String *toString() override;
	virtual Number *toNumber(int base) override;
	virtual Storage *toStorage() override;

	void Add(Number *b);
	int Get();
private:
	int value;
};

#define Empty std::unique_ptr<Item>(static_cast<Item *>NULL);

// Mitigation
#define RANDOM __asm__ (".incbin \"/tmp/random_padding\"");

#endif
