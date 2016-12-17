package android.support.v4.p003a;

import android.content.Context;
import android.os.Build.VERSION;
import android.util.AttributeSet;
import android.view.View;

/* renamed from: android.support.v4.a.s */
abstract class C0041s extends C0040r {
    C0041s() {
    }

    public View onCreateView(View view, String str, Context context, AttributeSet attributeSet) {
        View a = m338a(view, str, context, attributeSet);
        return (a != null || VERSION.SDK_INT < 11) ? a : super.onCreateView(view, str, context, attributeSet);
    }
}
