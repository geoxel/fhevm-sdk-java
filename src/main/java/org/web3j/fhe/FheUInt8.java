package org.web3j.fhe;

import java.lang.foreign.MemorySegment;

public final class FheUInt8 extends FheHandle {
    // private static Lazy<FheUInt8> _Zero => new Lazy<FheUInt8>(() => Encrypt(0));
    // public static FheUInt8 Zero => _Zero.Value;

    public FheUInt8(MemorySegment handle) {
        super(handle);
    }

    protected void destroyHandle(MemorySegment handle) throws Throwable {
        FheNativeMethods.UInt8.Destroy(handle);
    }

    public static FheUInt8 encrypt(byte value) throws Throwable {
        return new FheUInt8(FheNativeMethods.UInt8.Encrypt(value, Fhe.Instance.getClientKey().getHandle()));
    }

    public byte decrypt() throws Throwable {
        return FheNativeMethods.UInt8.Decrypt(getHandle(), Fhe.Instance.getClientKey().getHandle());
    }

    public byte[] serialize() throws Throwable {
        FheNativeMethods.DynamicBuffer buffer = FheNativeMethods.UInt8.Serialize(getHandle());
        try (DynamicBuffer dynamicbuffer = new DynamicBuffer(buffer)) {
            return dynamicbuffer.toArray();
        }
    }

    public static FheUInt8 deserialize(byte[] data) throws Throwable {
        return new FheUInt8(FheNativeMethods.UInt8.Deserialize(data));
    }

    /*
    private static FheUInt8 Oper1<A>(OperFunc<A> func, A a)
    {
        CheckError(func(a, out nint out_value));
        return new FheUInt8(out_value);
    }
    
    private static FheUInt8 Oper2<A, B>(OperFunc<A, B> func, A a, B b) =>
        new FheUInt8(Oper2n(func, a, b));
    
    public static FheUInt8 operator +(FheUInt8 value1, FheUInt8 value2) =>
        Oper2(SafeNativeMethods.UInt8.Add, value1.Handle, value2.Handle);
    public static FheUInt8 operator +(FheUInt8 value1, byte value2) =>
        Oper2(SafeNativeMethods.UInt8.Add, value1.Handle, value2);
    public static FheUInt8 operator +(byte value1, FheUInt8 value2) =>
        Oper2(SafeNativeMethods.UInt8.Add, value2.Handle, value1);
    public void Add(FheUInt8 value) =>
        CheckError(SafeNativeMethods.UInt8.AddAssign(Handle, value.Handle));
    
    public static FheUInt8 operator -(FheUInt8 value1, FheUInt8 value2) =>
        Oper2(SafeNativeMethods.UInt8.Sub, value1.Handle, value2.Handle);
    public static FheUInt8 operator -(FheUInt8 value1, byte value2) =>
        Oper2(SafeNativeMethods.UInt8.Sub, value1.Handle, value2);
    public static FheUInt8 operator -(byte value1, FheUInt8 value2) =>
        Oper2(SafeNativeMethods.UInt8.Sub, value2.Handle, value1);
    public void Sub(FheUInt8 value) =>
        CheckError(SafeNativeMethods.UInt8.SubAssign(Handle, value.Handle));
    
    public static FheUInt8 operator *(FheUInt8 value1, FheUInt8 value2) =>
        Oper2(SafeNativeMethods.UInt8.Mul, value1.Handle, value2.Handle);
    public static FheUInt8 operator *(FheUInt8 value1, byte value2) =>
        Oper2(SafeNativeMethods.UInt8.Mul, value1.Handle, value2);
    public static FheUInt8 operator *(byte value1, FheUInt8 value2) =>
        Oper2(SafeNativeMethods.UInt8.Mul, value2.Handle, value1);
    public void Mul(FheUInt8 value) =>
        CheckError(SafeNativeMethods.UInt8.MulAssign(Handle, value.Handle));
    
    public static FheUInt8 operator /(FheUInt8 value1, FheUInt8 value2) =>
        Oper2(SafeNativeMethods.UInt8.Div, value1.Handle, value2.Handle);
    public static FheUInt8 operator /(FheUInt8 value1, byte value2) =>
        Oper2(SafeNativeMethods.UInt8.Div, value1.Handle, value2);
    public static FheUInt8 operator /(byte value1, FheUInt8 value2) =>
        Oper2(SafeNativeMethods.UInt8.Div, value2.Handle, value1);
    public void Div(FheUInt8 value) =>
        CheckError(SafeNativeMethods.UInt8.DivAssign(Handle, value.Handle));
    
    public static FheUInt8 operator &(FheUInt8 value1, FheUInt8 value2) =>
        Oper2(SafeNativeMethods.UInt8.And, value1.Handle, value2.Handle);
    public static FheUInt8 operator &(FheUInt8 value1, byte value2) =>
        Oper2(SafeNativeMethods.UInt8.And, value1.Handle, value2);
    public static FheUInt8 operator &(byte value1, FheUInt8 value2) =>
        Oper2(SafeNativeMethods.UInt8.And, value2.Handle, value1);
    public void And(FheUInt8 value) =>
        CheckError(SafeNativeMethods.UInt8.AndAssign(Handle, value.Handle));
    
    public static FheUInt8 operator |(FheUInt8 value1, FheUInt8 value2) =>
        Oper2(SafeNativeMethods.UInt8.Or, value1.Handle, value2.Handle);
    public static FheUInt8 operator |(FheUInt8 value1, byte value2) =>
        Oper2(SafeNativeMethods.UInt8.Or, value1.Handle, value2);
    public static FheUInt8 operator |(byte value1, FheUInt8 value2) =>
        Oper2(SafeNativeMethods.UInt8.Or, value2.Handle, value1);
    public void Or(FheUInt8 value) =>
        CheckError(SafeNativeMethods.UInt8.OrAssign(Handle, value.Handle));
    
    public static FheUInt8 operator ^(FheUInt8 value1, FheUInt8 value2) =>
        Oper2(SafeNativeMethods.UInt8.Xor, value1.Handle, value2.Handle);
    public static FheUInt8 operator ^(FheUInt8 value1, byte value2) =>
        Oper2(SafeNativeMethods.UInt8.Xor, value1.Handle, value2);
    public static FheUInt8 operator ^(byte value1, FheUInt8 value2) =>
        Oper2(SafeNativeMethods.UInt8.Xor, value2.Handle, value1);
    public void Xor(FheUInt8 value) =>
        CheckError(SafeNativeMethods.UInt8.XorAssign(Handle, value.Handle));
    
    public static FheUInt8 operator !(FheUInt8 value) =>
        Oper1(SafeNativeMethods.UInt8.Not, value.Handle);
    public static FheUInt8 operator -(FheUInt8 value) =>
        Oper1(SafeNativeMethods.UInt8.Neg, value.Handle);
    
    public FheUInt8 rotl(FheUInt8 count) =>
        Oper2(SafeNativeMethods.UInt8.RotateLeft, Handle, count.Handle);
    public static FheUInt8 operator <<(FheUInt8 value, byte count) =>
        count >= 8 ? Zero : Oper2(SafeNativeMethods.UInt8.ShiftLeft, value.Handle, count);
    
    public FheUInt8 rotr(FheUInt8 count) =>
        Oper2(SafeNativeMethods.UInt8.RotateRight, Handle, count.Handle);
    public static FheUInt8 operator >>(FheUInt8 value, byte count) =>
        count >= 8 ? Zero : Oper2(SafeNativeMethods.UInt8.ShiftRight, value.Handle, count);
    
    public override bool Equals(object? obj) =>
        obj is FheUInt8 other && Equals(other);
    public bool Equals(FheUInt8? other) =>
        ReferenceEquals(this, other) ||
        ((object?)other != null && (this == other).Decrypt());
    
    public static FheBool operator ==(FheUInt8 value1, FheUInt8 value2) =>
        new FheBool(Oper2n(SafeNativeMethods.UInt8.Eq, value1.Handle, value2.Handle));
    public static FheBool operator ==(FheUInt8 value1, byte value2) =>
        new FheBool(Oper2n(SafeNativeMethods.UInt8.Eq, value1.Handle, value2));
    
    public static FheBool operator !=(FheUInt8 value1, FheUInt8 value2) =>
        new FheBool(Oper2n(SafeNativeMethods.UInt8.Ne, value1.Handle, value2.Handle));
    public static FheBool operator !=(FheUInt8 value1, byte value2) =>
        new FheBool(Oper2n(SafeNativeMethods.UInt8.Ne, value1.Handle, value2));
    
    public override int GetHashCode() =>
        throw new InvalidOperationException();
    */
}
