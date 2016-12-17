package android.support.v7.p014a;

import android.os.Message;
import android.view.View;
import android.view.View.OnClickListener;

/* renamed from: android.support.v7.a.f */
class C0216f implements OnClickListener {
    final /* synthetic */ C0215e f774a;

    C0216f(C0215e c0215e) {
        this.f774a = c0215e;
    }

    public void onClick(View view) {
        Message obtain = (view != this.f774a.f761n || this.f774a.f763p == null) ? (view != this.f774a.f764q || this.f774a.f766s == null) ? (view != this.f774a.f767t || this.f774a.f769v == null) ? null : Message.obtain(this.f774a.f769v) : Message.obtain(this.f774a.f766s) : Message.obtain(this.f774a.f763p);
        if (obtain != null) {
            obtain.sendToTarget();
        }
        this.f774a.f746M.obtainMessage(1, this.f774a.f749b).sendToTarget();
    }
}
