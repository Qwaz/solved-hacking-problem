package android.support.v4.widget;

import android.content.Context;
import android.database.Cursor;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

public abstract class as extends C0176m {
    private int f540j;
    private int f541k;
    private LayoutInflater f542l;

    public as(Context context, int i, Cursor cursor, boolean z) {
        super(context, cursor, z);
        this.f541k = i;
        this.f540j = i;
        this.f542l = (LayoutInflater) context.getSystemService("layout_inflater");
    }

    public View m1465a(Context context, Cursor cursor, ViewGroup viewGroup) {
        return this.f542l.inflate(this.f540j, viewGroup, false);
    }

    public View m1466b(Context context, Cursor cursor, ViewGroup viewGroup) {
        return this.f542l.inflate(this.f541k, viewGroup, false);
    }
}
