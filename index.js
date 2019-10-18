var fs = require('fs');

//create a stream of 188 bytes

const fileUrl = new URL('file:/d:/Web Dev/TransportStream/Self TS Analyzer/media/Tiny_Test_TS.ts');
const input = fs.createReadStream(fileUrl, { highWaterMark: 188 });
const { Transform } = require('stream');

const readTransform = new Transform({
    transform(chunk, encoding, next) {
        readTSPackets(chunk);
        next()
    }
});


//read TS packets and transform to JSON file

const readTSPackets = (chunk) => {
    const header = chunk.readUInt32BE(0); //first 4 bytes
    let packet = {
        type: "TSPacket",
        packetSync: (header & 0xff000000) >> 24,
        transportErrorIndicator: (header & 0x800000) !== 0,
        payloadUnitStartIndicator: (header & 0x400000) !== 0,
        transportPriority: (header & 0x200000) !== 0,
        pid: (header & 0x1fff00) >>> 8,
        scramblingControl: (header & 0xc0) >>> 6,
        adaptationFieldControl: (header & 0x30) >>> 4,
        continuityCounter: (header & 0xf)
    };

    //Check adaptation field 
    if ((packet.adaptationFieldControl & 0x02) !== 0) {
        let adaptationFieldLength = chunk.readUInt8(4);
        if (adaptationFieldLength === 0) {
            packet.adaptationField = {
                type: 'AdaptationField',
                adaptationFieldLength: 0
            };
        } else {
            let flags = chunk.readUInt8(5);
            packet.adaptationField = {
                type: 'AdaptationField',
                adaptationFieldLength: adaptationFieldLength,
                discontinuityIndicator: (flags & 0x80) !== 0,
                randomAccessIndicator: (flags & 0x40) !== 0,
                elementaryStreamPriorityIndicator: (flags & 0x20) !== 0,
                pcrFlag: (flags & 0x10) !== 0,
                opcrFlag: (flags & 0x08) !== 0,
                splicingPointFlag: (flags & 0x04) !== 0,
                transportPrivateDataFlag: (flags & 0x02) !== 0,
                adaptationFieldExtensionFlag: (flags & 0x01) !== 0
            }
        }
    }
    if ((packet.adaptationFieldControl & 0x01) !== 0) {
        packet.payload = packet.adaptationField ? 
        chunk.slice(5+packet.adaptationField.adaptationFieldLength):
        chunk.slice(4);
    }

    console.log(packet);
    console.log("________________________________________________")

    return packet;
};

// pipe read stream into transform stram
input.pipe(readTransform);

//update UI