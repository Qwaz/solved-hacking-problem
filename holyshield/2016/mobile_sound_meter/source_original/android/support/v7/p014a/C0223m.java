package android.support.v7.p014a;

import android.content.Context;
import android.database.Cursor;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckedTextView;
import android.widget.CursorAdapter;
import android.widget.ListView;

/* renamed from: android.support.v7.a.m */
class C0223m extends CursorAdapter {
    final /* synthetic */ ListView f828a;
    final /* synthetic */ C0215e f829b;
    final /* synthetic */ C0221k f830c;
    private final int f831d;
    private final int f832e;

    C0223m(C0221k c0221k, Context context, Cursor cursor, boolean z, ListView listView, C0215e c0215e) {
        this.f830c = c0221k;
        this.f828a = listView;
        this.f829b = c0215e;
        super(context, cursor, z);
        Cursor cursor2 = getCursor();
        this.f831d = cursor2.getColumnIndexOrThrow(this.f830c.f795I);
        this.f832e = cursor2.getColumnIndexOrThrow(this.f830c.f796J);
    }

    public void bindView(View view, Context context, Cursor cursor) {
        ((CheckedTextView) view.findViewById(16908308)).setText(cursor.getString(this.f831d));
        this.f828a.setItemChecked(cursor.getPosition(), cursor.getInt(this.f832e) == 1);
    }

    public View newView(Context context, Cursor cursor, ViewGroup viewGroup) {
        return this.f830c.f801b.inflate(this.f829b.f742I, viewGroup, false);
    }
}
