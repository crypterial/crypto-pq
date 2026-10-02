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

      this.buffer.set(data.subarray(0, offset), this.buffered);

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

    this.buffer.set(data.subarray(offset), 0);

    this.buffered = data.length - offset;
  }

  protected abstract process(data: Uint8Array, offset: number): void;
}
