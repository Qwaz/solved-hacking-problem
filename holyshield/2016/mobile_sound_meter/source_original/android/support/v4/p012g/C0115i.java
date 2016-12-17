package android.support.v4.p012g;

import java.util.Iterator;

/* renamed from: android.support.v4.g.i */
final class C0115i implements Iterator {
    final int f396a;
    int f397b;
    int f398c;
    boolean f399d;
    final /* synthetic */ C0108h f400e;

    C0115i(C0108h c0108h, int i) {
        this.f400e = c0108h;
        this.f399d = false;
        this.f396a = i;
        this.f397b = c0108h.m607a();
    }

    public boolean hasNext() {
        return this.f398c < this.f397b;
    }

    public Object next() {
        Object a = this.f400e.m609a(this.f398c, this.f396a);
        this.f398c++;
        this.f399d = true;
        return a;
    }

    public void remove() {
        if (this.f399d) {
            this.f398c--;
            this.f397b--;
            this.f399d = false;
            this.f400e.m611a(this.f398c);
            return;
        }
        throw new IllegalStateException();
    }
}
