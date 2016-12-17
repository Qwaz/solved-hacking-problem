package android.support.v4.p003a;

import android.view.LayoutInflater;
import android.view.View;
import android.view.Window;
import java.io.FileDescriptor;
import java.io.PrintWriter;

/* renamed from: android.support.v4.a.y */
class C0047y extends ac {
    final /* synthetic */ C0045w f330a;

    public C0047y(C0045w c0045w) {
        this.f330a = c0045w;
        super(c0045w);
    }

    public View m421a(int i) {
        return this.f330a.findViewById(i);
    }

    public void m422a(String str, FileDescriptor fileDescriptor, PrintWriter printWriter, String[] strArr) {
        this.f330a.dump(str, fileDescriptor, printWriter, strArr);
    }

    public boolean m423a() {
        Window window = this.f330a.getWindow();
        return (window == null || window.peekDecorView() == null) ? false : true;
    }

    public boolean m424a(C0042t c0042t) {
        return !this.f330a.isFinishing();
    }

    public LayoutInflater m425b() {
        return this.f330a.getLayoutInflater().cloneInContext(this.f330a);
    }

    public void m426b(C0042t c0042t) {
        this.f330a.m414a(c0042t);
    }

    public void m427c() {
        this.f330a.m419d();
    }

    public boolean m428d() {
        return this.f330a.getWindow() != null;
    }

    public int m429e() {
        Window window = this.f330a.getWindow();
        return window == null ? 0 : window.getAttributes().windowAnimations;
    }
}
