typedef bit<9> egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


#define TYPE_IPV4 0x800

header ethernet_t {
	macAddr_t dstAddr;
	macAddr_t srcAddr;
	bit<16> etherType;
}

header ipv4_t {
	bit<4> version;
	bit<4> ihl;
	bit<8> diffserv;
	bit<16> totalLen;
	bit<16> identification;
	bit<3> flags;
	bit<13> fragOffset;
	bit<8> ttl;
	bit<8> protocol;
	bit<16> hdrChecksum;
	ip4Addr_t srcAddr;
	ip4Addr_t dstAddr;
}


struct headers {
	ethernet_t ethernet;
	ipv4_t ipv4;

}
	
struct metadata {
	bit<64> flowID;
	bit<32> currentIndex;
	bit<32> currentValue;
	bit<64> currentKey;

        bit<32> heapIndex;
	bit<32> heapIndex0;
	bit<32> heapIndex1;
	bit<32> heapIndex2;

	bit<32> heapCount;
	bit<32> heapCount0;
	bit<32> heapCount1;
	bit<32> heapCount2;

	bit<32> insertItemValue;
	bit<32> insertItemValue0;
	bit<32> insertItemValue1;
	bit<32> insertItemValue2;

	bit<32> insertIndex;
	bit<32> insertIndex0;
	bit<32> insertIndex1;
	bit<32> insertIndex2;

        //cannot compare register directly , so read first to meta
	bit<32> topTempMinvalue;
	bit<32> topMinvaluePos;

        bit<32> aggIndex;
	bit<5> aggValue;


	bit<1> insertFlag;
	bit<1> insertFlag0;
	bit<1> insertFlag1;
	bit<1> insertFlag2;

	bit<32> packetNum;
	bit<32> positionInReplace;
	bit<32> positionInUpdate;


}
