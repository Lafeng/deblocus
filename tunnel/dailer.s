#include "textflag.h"

TEXT ·resolveAddrList(SB),NOSPLIT,$0
	JMP	net·resolveAddrList(SB)

TEXT ·dialSerial(SB),NOSPLIT,$0
	JMP	net·dialSerial(SB)
