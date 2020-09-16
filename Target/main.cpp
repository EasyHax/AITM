#include <iostream>
#include <chrono>
#include <thread>

int main( void );

void print_ebp() {

	int pebp;
	_asm mov pebp, ebp;

	std::cout << "[+] EBP REGISTER : " << pebp << std::endl;
}


int main( void ) {

	while ( true ) {
		print_ebp();
		std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
	}

	return 0;
}