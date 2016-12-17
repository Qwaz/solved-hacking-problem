package android.support.v7.p014a;

import android.content.Context;
import android.widget.ArrayAdapter;

/* renamed from: android.support.v7.a.r */
class C0228r extends ArrayAdapter {
    public C0228r(Context context, int i, int i2, CharSequence[] charSequenceArr) {
        super(context, i, i2, charSequenceArr);
    }

    public long getItemId(int i) {
        return (long) i;
    }

    public boolean hasStableIds() {
        return true;
    }
}
