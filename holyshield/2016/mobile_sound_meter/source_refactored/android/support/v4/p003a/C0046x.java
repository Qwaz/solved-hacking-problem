package android.support.v4.p003a;

import android.os.Handler;
import android.os.Message;
import android.support.v7.p015b.C0243l;

/* renamed from: android.support.v4.a.x */
class C0046x extends Handler {
    final /* synthetic */ C0045w f329a;

    C0046x(C0045w c0045w) {
        this.f329a = c0045w;
    }

    public void handleMessage(Message message) {
        switch (message.what) {
            case C0243l.View_android_focusable /*1*/:
                if (this.f329a.f322e) {
                    this.f329a.m415a(false);
                }
            case C0243l.View_paddingStart /*2*/:
                this.f329a.m417b();
                this.f329a.f319b.m107n();
            default:
                super.handleMessage(message);
        }
    }
}
