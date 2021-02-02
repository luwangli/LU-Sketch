//此版本实现了heavy hitter和从二端口进入即更新的功能
//希望可以实现一个计数器，记录heap更新的发生在第几个数据包
//思路：两个计数器，一个计数器记录插入数据包的数量，另一个计数器组记录

#include <core.p4>
#include <v1model.p4>
#include "include/headers.p4"
#include "include/parsers.p4"


const bit<8> QUERY_PROTOCOL = 63;
const bit<8> TCP_PROTOCOL = 0x06;

const bit<32> BUFFER_THRESHOLD = 1;//set to 2 for debug quickly
register<bit<64>>(32) BufferKey;
register<bit<5>>(32) BufferValue;

register<bit<32>>(1) Top_temp_minvalue;
register<bit<32>>(1) Top_minvalue_pos;
//Top_temp_minvalue = 0;

register<bit<32>>(1) Packet_num;
register<bit<32>>(100) Replace_node_time;
register<bit<32>>(300) Update_count_time;
register<bit<32>>(1) Position_in_count_update;
register<bit<32>>(1) Position_in_node_replace;

#define ENTRIES_PER_TABLE 1000
#define ENTRY_WIDTH 32
#define TOP_K 10
//#define TOP_K 20
#define FLAG_WIDTH 1

//cm-flag structure
#define CM_INIT(num) register<bit<ENTRY_WIDTH>>(ENTRIES_PER_TABLE) Cm##num
#define FLAG_INIT(num) register<bit<FLAG_WIDTH>>(ENTRIES_PER_TABLE) Flag##num

//heap structure
/*
#define HEAP_KEY_INIT(num) register<bit<64>>(TOP_K) Heap_key##num
#define HEAP_COUNT_INIT(num) register<bit<32>>(TOP_K) Heap_count##num
#define HEAP_INDEX_ZERO_INIT(num) register<bit<16>>(TOP_K) Heap_index_zero##num
#define HEAP_INDEX_ONE_INIT(num) register<bit<16>>(TOP_K) Heap_index_one##num
#define HEAP_INDEX_TWO_INIT(num) register<bit<16>>(TOP_K) Heap_index_two##num
*/
register<bit<64>>(TOP_K) Heap_key;
register<bit<32>>(TOP_K) Heap_count;
register<bit<32>>(TOP_K) Heap_index_zero;
register<bit<32>>(TOP_K) Heap_index_one;
register<bit<32>>(TOP_K) Heap_index_two;

//CM operation
#define GET_ENTRY(num,seed,flow_key) hash(meta.currentIndex, HashAlgorithm.crc32,(bit<32>)0, {flow_key,seed},(bit<32>) ENTRIES_PER_TABLE);\
Cm##num.read(meta.currentValue, meta.currentIndex);

#define WRITE_ENTRY(num, flow_value) Cm##num.write(meta.currentIndex, meta.currentValue + flow_value);

#define INSERT_STAGE(num,seed,flow_key,flow_value) {\
GET_ENTRY(num,seed,flow_key);\
WRITE_ENTRY(num,flow_value);\
}

//init is too trival, for no loop function ：P
CM_INIT(0);
CM_INIT(1);
CM_INIT(2);
FLAG_INIT(0);
FLAG_INIT(1);
FLAG_INIT(2);

/*********************************header **************************************/

/*********************************parser **************************************/


/*********************************checksum verification************************/

control MyVerifyChecksum(inout headers hdr,inout metadata meta) {
	apply { }
}

control MyIngress( 	inout headers hdr,
			inout metadata meta,
			inout standard_metadata_t standard_metadata) {

     //   bit<5> tmp_value;

	action drop() {
		mark_to_drop(standard_metadata);
	}

	action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
		standard_metadata.egress_spec = port;
		hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
		hdr.ethernet.dstAddr = dstAddr;
		hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
	}

	action buffer_increment() {
//	        BufferValue.read(meta.aggValue, meta.currentIndex);
	        BufferValue.write(meta.aggIndex, meta.aggValue+1);
	}


	action buffer_get_position() {
	        meta.flowID[31:0] = hdr.ipv4.srcAddr;
	//        meta.flowID[63:32] = hdr.ipv4.dstAddr;
	        hash(meta.aggIndex, HashAlgorithm.crc32, (bit<4>)0, {meta.flowID}, (bit<6>)32);
	        BufferKey.read(meta.currentKey, meta.aggIndex);
	        BufferValue.read(meta.aggValue, meta.aggIndex);
	        meta.currentValue = (bit<32>) meta.aggValue;
	}

	action buffer_insert() {
	        BufferKey.write(meta.aggIndex, meta.flowID);
	        BufferValue.write(meta.aggIndex, 1);
	}

	action min_cnt(inout bit<32> mincnt, in bit<32> cnt0,in bit<32> cnt1 ,in bit<32> cnt2)
	{
	        if(cnt0 < cnt1)
	        {
	            mincnt = cnt0;
	        }else {
	            mincnt = cnt1;
	        }
	        if( mincnt > cnt2)  mincnt = cnt2;
	}

	action min_flag(inout bit<1> minflag, in bit<1> flag0, in bit<1> flag1, in bit<1> flag2)
	{
		if(flag0 < flag1)
	        {
	            minflag = flag0;
	        }else {
	            minflag = flag1;
	        }
	        if( minflag > flag2)  minflag = flag2;

	}


	action heap_replace(in bit<64> flow_key)
	{
	    Heap_key.write(meta.topMinvaluePos, flow_key);
	    Heap_count.write(meta.topMinvaluePos, meta.insertItemValue);
	    Heap_index_zero.write(meta.topMinvaluePos, meta.insertIndex0);
	    Heap_index_one.write(meta.topMinvaluePos, meta.insertIndex1);
	    Heap_index_two.write(meta.topMinvaluePos, meta.insertIndex2);
	}

	action flag_delete()//mininum value in heap, this element's flag should change to be 0
	{
	    Flag0.write(meta.heapIndex0,0);
	    Flag1.write(meta.heapIndex1,0);
	    Flag2.write(meta.heapIndex2,0);

	}

	action flag_add()//new item replace, correponding flag position set 1
	{
	    Flag0.write(meta.insertIndex0,1);
	    Flag1.write(meta.insertIndex1,1);
	    Flag2.write(meta.insertIndex2,1);
	}
	action update_minheap_value_and_flag_pos(in bit<32> pos)
        {
                Heap_index_zero.read(meta.heapIndex0,pos);
                Heap_index_one.read(meta.heapIndex1,pos);
                Heap_index_two.read(meta.heapIndex2,pos);
                //update Flag
                Flag0.write(meta.heapIndex0,1);
                Flag1.write(meta.heapIndex1,1);
                Flag2.write(meta.heapIndex2,1);

                //update HEAP.count
                Cm0.read(meta.heapCount0,meta.heapIndex0);
                Cm1.read(meta.heapCount1,meta.heapIndex1);
                Cm2.read(meta.heapCount2,meta.heapIndex2);

                min_cnt(meta.heapCount, meta.heapCount0,meta.heapCount1,meta.heapCount2);
                Heap_count.write(pos,meta.heapCount);

                if(meta.heapCount < meta.topTempMinvalue)
                {
                    meta.topTempMinvalue = meta.heapCount;//update
                    meta.topMinvaluePos = pos;

                }
        }



	action update_minheap_value_and_flag()//p4 not support loop ? cry :(
	{
	        meta.topTempMinvalue = 1<<30;
	        update_minheap_value_and_flag_pos(0);
	        update_minheap_value_and_flag_pos(1);
	        update_minheap_value_and_flag_pos(2);
	        update_minheap_value_and_flag_pos(3);
	        update_minheap_value_and_flag_pos(4);
	        update_minheap_value_and_flag_pos(5);
	        update_minheap_value_and_flag_pos(6);
	        update_minheap_value_and_flag_pos(7);
	        update_minheap_value_and_flag_pos(8);
	        update_minheap_value_and_flag_pos(9);
	    //    update_minheap_value_and_flag_pos(10);
	    //    update_minheap_value_and_flag_pos(11);
	    //    update_minheap_value_and_flag_pos(12);
	    //    update_minheap_value_and_flag_pos(13);
	  //      update_minheap_value_and_flag_pos(14);
	  //      update_minheap_value_and_flag_pos(15);
	  //      update_minheap_value_and_flag_pos(16);
	  //      update_minheap_value_and_flag_pos(17);
	 //       update_minheap_value_and_flag_pos(18);
	 //       update_minheap_value_and_flag_pos(19);
	        Top_temp_minvalue.write(0,meta.topTempMinvalue);//write into register
                Top_minvalue_pos.write(0,meta.topMinvaluePos);
                //modify
                Heap_index_zero.read(meta.heapIndex0,meta.topMinvaluePos);
                Heap_index_one.read(meta.heapIndex1, meta.topMinvaluePos);
                Heap_index_two.read(meta.heapIndex2, meta.topMinvaluePos);

                Position_in_count_update.read(meta.positionInUpdate,0);
                Update_count_time.write(meta.positionInUpdate,meta.packetNum);
                Position_in_count_update.write(0,meta.positionInUpdate+1);

	}

	action insert_flow_to_CM(in bit<64> flow_key, in bit<32> flow_value) {

	        INSERT_STAGE(0,20w1111,flow_key,flow_value);
	        //currentIndex is the position in Cm and Flag
	        meta.insertItemValue0 = meta.currentValue + flow_value;//update insert item's estimated value
	        meta.insertIndex0 = meta.currentIndex;//get insert item's position in CM
	  //      Flag0.read(meta.insertFlag0, meta.insertIndex0);//get insert item's flag in Flag

	        INSERT_STAGE(1,20w2222,flow_key,flow_value);
	        meta.insertItemValue1 = meta.currentValue + flow_value;//update insert item's estimated value
	        meta.insertIndex1 = meta.currentIndex;//get insert item's position in CM
	  //     Flag1.read(meta.insertFlag1, meta.insertIndex1);//get insert item's flag in Flag

	        INSERT_STAGE(2,20w3333,flow_key,flow_value);
	        meta.insertItemValue2 = meta.currentValue + flow_value;//update insert item's estimated value
	        meta.insertIndex2 = meta.currentIndex;//get insert item's position in CM
	  //      Flag2.read(meta.insertFlag2, meta.insertIndex2);//get insert item's flag in Flag

	  //      min_flag(meta.insertFlag,meta.insertFlag0,meta.insertFlag1,meta.insertFlag2);
	        min_cnt(meta.insertItemValue, meta.insertItemValue0, meta.insertItemValue1, meta.insertItemValue2);
	}
	action get_flag_from_CM() {
	        Flag0.read(meta.insertFlag0, meta.insertIndex0);
	        Flag1.read(meta.insertFlag1, meta.insertIndex1);
	        Flag2.read(meta.insertFlag2, meta.insertIndex2);
	        min_flag(meta.insertFlag, meta.insertFlag0, meta.insertFlag1, meta.insertFlag2);
	}


	table ipv4_lpm {
		key = {
			hdr.ipv4.dstAddr: lpm;
		}
		actions = {
			ipv4_forward;
			drop;
			NoAction;
		}
		size = 1024;
		default_action = NoAction();
	}

	apply {
		if(hdr.ipv4.isValid()) {
		    if(hdr.ipv4.protocol == QUERY_PROTOCOL){
		         update_minheap_value_and_flag();

		    }
		    else{

		        //
		        Packet_num.read(meta.packetNum,0);
		        Packet_num.write(0,meta.packetNum+1);

		        // get newIterm's position in buffer
		        buffer_get_position();
		        //if this position is null
		        if(meta.currentValue == 0) {
		                buffer_insert();
		        }
		        //if this position is not null
		        //  and the key in this position equal the new arrived item, value add 1
		        //   else new item replace the old key
		        else if(meta.currentKey == meta.flowID) {
		                buffer_increment();
		                if(meta.currentValue + 1 >= BUFFER_THRESHOLD) {
		                        Top_temp_minvalue.read(meta.topTempMinvalue,0);
		                        Top_minvalue_pos.read(meta.topMinvaluePos,0);
		                        BufferValue.write(meta.aggIndex,0);
		                        BufferKey.write(meta.aggIndex,0);

		                        insert_flow_to_CM(meta.currentKey, meta.currentValue+1);
		                        get_flag_from_CM();



		                        if(meta.topTempMinvalue < meta.insertItemValue &&(meta.insertFlag == 0))
		                        {
		                            update_minheap_value_and_flag();//this will update Top_temp_minvalue ,Flag, heapCount
		                            get_flag_from_CM();
	                                    if(meta.topTempMinvalue < meta.insertItemValue &&(meta.insertFlag == 0))// if true , new item should add into heap,
	                                    {
	                                    //count for update time
	                                         Position_in_node_replace.read(meta.positionInReplace,0);
	                                         Replace_node_time.write(meta.positionInReplace,meta.packetNum);
	                                         Position_in_node_replace.write(0,meta.positionInReplace+1);
	                                    //

	                                        flag_delete();
	                                        heap_replace(meta.currentKey);
	                                        flag_add();
	                                    }

	                                }

		                }
		        }
		        else {
		                Top_temp_minvalue.read(meta.topTempMinvalue,0);
	                        Top_minvalue_pos.read(meta.topMinvaluePos,0);
		                insert_flow_to_CM(meta.currentKey, meta.currentValue);
		                get_flag_from_CM();
		                if(meta.topTempMinvalue < meta.insertItemValue &&(meta.insertFlag == 0))
		                {
		                    update_minheap_value_and_flag();//this will update Top_temp_minvalue ,Flag, heapCount
	                            get_flag_from_CM();
	                            if(meta.topTempMinvalue < meta.insertItemValue &&(meta.insertFlag == 0))// if true , new item should add into heap,
	                            {
	                            //count for update time
	                                Position_in_node_replace.read(meta.positionInReplace,0);
	                                Replace_node_time.write(meta.positionInReplace,meta.packetNum);
	                                Position_in_node_replace.write(0,meta.positionInReplace+1);
	                            //
	                                flag_delete();
	                                heap_replace(meta.currentKey);
	                                flag_add();
	                            }

	                        }
		                buffer_insert();
		        }


	//	        update_minheap_value_and_flag();
		        ipv4_lpm.apply();
		    }
	//	        update_minheap_value_and_flag();


		}
	}
}


control MyEgress(inout headers hdr,
		inout metadata meta,
		inout standard_metadata_t stadard_metadata) {
			apply{}
}


control MyComputeChecksum(inout headers hdr, inout metadata meta) {
	apply{
	    update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
	}
}

control MyDeparser(packet_out packet, in headers hdr) {
	apply{
		packet.emit(hdr.ethernet);
		packet.emit(hdr.ipv4);
	}
}

/*******SWITCH****/
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;


