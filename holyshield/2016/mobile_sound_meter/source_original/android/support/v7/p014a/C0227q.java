package android.support.v7.p014a;

import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;
import android.os.Handler;
import android.os.Message;
import android.support.v7.p015b.C0243l;
import java.lang.ref.WeakReference;

/* renamed from: android.support.v7.a.q */
final class C0227q extends Handler {
    private WeakReference f838a;

    public C0227q(DialogInterface dialogInterface) {
        this.f838a = new WeakReference(dialogInterface);
    }

    public void handleMessage(Message message) {
        switch (message.what) {
            case -3:
            case -2:
            case -1:
                ((OnClickListener) message.obj).onClick((DialogInterface) this.f838a.get(), message.what);
            case C0243l.View_android_focusable /*1*/:
                ((DialogInterface) message.obj).dismiss();
            default:
        }
    }
}
