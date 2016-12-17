package android.support.v7.p014a;

import android.content.Context;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.ListView;

/* renamed from: android.support.v7.a.l */
class C0222l extends ArrayAdapter {
    final /* synthetic */ ListView f826a;
    final /* synthetic */ C0221k f827b;

    C0222l(C0221k c0221k, Context context, int i, int i2, CharSequence[] charSequenceArr, ListView listView) {
        this.f827b = c0221k;
        this.f826a = listView;
        super(context, i, i2, charSequenceArr);
    }

    public View getView(int i, View view, ViewGroup viewGroup) {
        View view2 = super.getView(i, view, viewGroup);
        if (this.f827b.f789C != null && this.f827b.f789C[i]) {
            this.f826a.setItemChecked(i, true);
        }
        return view2;
    }
}
