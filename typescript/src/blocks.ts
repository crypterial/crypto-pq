export abstract class Blocks {
  protected readonly buffer: Uint8Array;

  protected buffered = 0;

  constructor(blockSize: number) {
    this.buffer = new Uint8Array(blockSize);
  }

  update(data: Uint8Array): void {
    const block = this.buffer.length;

    let offset = 0;

    if (this.buffered > 0) {
      offset = Math.min(block - this.buffered, data.length);

      copy(data, 0, this.buffer, this.buffered, offset);

      this.buffered += offset;

      if (this.buffered < block) {
        return;
      }

      this.process(this.buffer, 0);

      this.buffered = 0;
    }

    for (; offset + block <= data.length; offset += block) {
      this.process(data, offset);
    }

    copy(data, offset, this.buffer, 0, data.length - offset);

    this.buffered = data.length - offset;
  }

  protected abstract process(data: Uint8Array, offset: number): void;
}

// Short copies, the usual case here, are cheaper as a loop than as a subarray view and set().
function copy(from: Uint8Array, fromOffset: number, to: Uint8Array, toOffset: number, count: number): void {
  if (count > 64) {
    to.set(from.subarray(fromOffset, fromOffset + count), toOffset);
  } else {
    for (let i = 0; i < count; i++) {
      to[toOffset + i] = from[fromOffset + i];
    }
  }
}
