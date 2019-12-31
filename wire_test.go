package dns

import (
	"reflect"
	"testing"
	"time"
)

func TestRecord(t *testing.T) {
	mname, err := NameWithString("ns1.tessier-ashpool.net")
	if err != nil {
		t.Fatal(err)
	}
	rname, err := NameWithString("host\000admin.tessier-ashpool.net")
	if err != nil {
		t.Fatal(err)
	}
	soa := &SOARecord{
		MName:   mname,
		ReName:  rname,
		Serial:  1234,
		Refresh: 10800 * time.Second,
		Retry:   10800 * time.Second,
		Expire:  604800 * time.Second,
		Minimum: 3600 * time.Second,
	}

	dname, err := NameWithString("tessier-ashpool.net")
	if err != nil {
		t.Fatal(err)
	}

	record := Record{
		RecordHeader: RecordHeader{
			Name:  dname,
			TTL:   600 * time.Second,
			Class: INClass,
		},
		RecordData: soa,
	}

	buffer := make([]byte, 512)
	c := NewWireCodec(buffer)

	err = c.Encode(&record)
	if err != nil {
		t.Fatal(err)
	}

	buffer = buffer[:c.Offset()]
	dump(buffer)
	c = NewWireCodec(buffer)

	record2 := Record{}
	err = c.Decode(&record2)
	if err != nil {
		t.Fatal(err)
	}

	soa2, ok := record2.RecordData.(*SOARecord)
	if !ok {
		t.Fatalf("RecordData is %T\n", record2.RecordData)
	}

	record.RecordHeader.Type = record2.RecordHeader.Type     // fill in parse only for DeepEqual
	record.RecordHeader.Length = record2.RecordHeader.Length // fill in parse only for DeepEqual
	if !reflect.DeepEqual(record.RecordHeader, record2.RecordHeader) {
		t.Fatalf("header %+v, parsed header %+v", record.RecordHeader, record2.RecordHeader)
	}
	if !reflect.DeepEqual(soa, soa2) {
		t.Fatalf("soa %+v, parsed soa %+v", soa, soa2)
	}

	t.Log(&record2)
}
