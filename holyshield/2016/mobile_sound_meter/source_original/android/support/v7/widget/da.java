package android.support.v7.widget;

import android.app.SearchManager;
import android.app.SearchableInfo;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.content.res.Resources.NotFoundException;
import android.database.Cursor;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.Drawable.ConstantState;
import android.net.Uri;
import android.net.Uri.Builder;
import android.os.Bundle;
import android.support.v4.p002b.C0020a;
import android.support.v4.widget.as;
import android.support.v7.p015b.C0233b;
import android.support.v7.p015b.C0238g;
import android.text.SpannableString;
import android.text.TextUtils;
import android.text.style.TextAppearanceSpan;
import android.util.Log;
import android.util.TypedValue;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.List;
import java.util.WeakHashMap;

class da extends as implements OnClickListener {
    private final SearchManager f1484j;
    private final SearchView f1485k;
    private final SearchableInfo f1486l;
    private final Context f1487m;
    private final WeakHashMap f1488n;
    private final int f1489o;
    private boolean f1490p;
    private int f1491q;
    private ColorStateList f1492r;
    private int f1493s;
    private int f1494t;
    private int f1495u;
    private int f1496v;
    private int f1497w;
    private int f1498x;

    public da(Context context, SearchView searchView, SearchableInfo searchableInfo, WeakHashMap weakHashMap) {
        super(context, searchView.getSuggestionRowLayout(), null, true);
        this.f1490p = false;
        this.f1491q = 1;
        this.f1493s = -1;
        this.f1494t = -1;
        this.f1495u = -1;
        this.f1496v = -1;
        this.f1497w = -1;
        this.f1498x = -1;
        this.f1484j = (SearchManager) this.d.getSystemService("search");
        this.f1485k = searchView;
        this.f1486l = searchableInfo;
        this.f1489o = searchView.getSuggestionCommitIconResId();
        this.f1487m = context;
        this.f1488n = weakHashMap;
    }

    private Drawable m2677a(ComponentName componentName) {
        Object obj = null;
        String flattenToShortString = componentName.flattenToShortString();
        if (this.f1488n.containsKey(flattenToShortString)) {
            ConstantState constantState = (ConstantState) this.f1488n.get(flattenToShortString);
            return constantState == null ? null : constantState.newDrawable(this.f1487m.getResources());
        } else {
            Drawable b = m2684b(componentName);
            if (b != null) {
                obj = b.getConstantState();
            }
            this.f1488n.put(flattenToShortString, obj);
            return b;
        }
    }

    private Drawable m2678a(String str) {
        if (str == null || str.length() == 0 || "0".equals(str)) {
            return null;
        }
        Drawable b;
        try {
            int parseInt = Integer.parseInt(str);
            String str2 = "android.resource://" + this.f1487m.getPackageName() + "/" + parseInt;
            b = m2686b(str2);
            if (b != null) {
                return b;
            }
            b = C0020a.m74a(this.f1487m, parseInt);
            m2683a(str2, b);
            return b;
        } catch (NumberFormatException e) {
            b = m2686b(str);
            if (b != null) {
                return b;
            }
            b = m2685b(Uri.parse(str));
            m2683a(str, b);
            return b;
        } catch (NotFoundException e2) {
            Log.w("SuggestionsAdapter", "Icon resource not found: " + str);
            return null;
        }
    }

    private static String m2679a(Cursor cursor, int i) {
        String str = null;
        if (i != -1) {
            try {
                str = cursor.getString(i);
            } catch (Throwable e) {
                Log.e("SuggestionsAdapter", "unexpected error retrieving valid column from cursor, did the remote process die?", e);
            }
        }
        return str;
    }

    public static String m2680a(Cursor cursor, String str) {
        return m2679a(cursor, cursor.getColumnIndex(str));
    }

    private void m2681a(ImageView imageView, Drawable drawable, int i) {
        imageView.setImageDrawable(drawable);
        if (drawable == null) {
            imageView.setVisibility(i);
            return;
        }
        imageView.setVisibility(0);
        drawable.setVisible(false, false);
        drawable.setVisible(true, false);
    }

    private void m2682a(TextView textView, CharSequence charSequence) {
        textView.setText(charSequence);
        if (TextUtils.isEmpty(charSequence)) {
            textView.setVisibility(8);
        } else {
            textView.setVisibility(0);
        }
    }

    private void m2683a(String str, Drawable drawable) {
        if (drawable != null) {
            this.f1488n.put(str, drawable.getConstantState());
        }
    }

    private Drawable m2684b(ComponentName componentName) {
        PackageManager packageManager = this.d.getPackageManager();
        try {
            ActivityInfo activityInfo = packageManager.getActivityInfo(componentName, 128);
            int iconResource = activityInfo.getIconResource();
            if (iconResource == 0) {
                return null;
            }
            Drawable drawable = packageManager.getDrawable(componentName.getPackageName(), iconResource, activityInfo.applicationInfo);
            if (drawable != null) {
                return drawable;
            }
            Log.w("SuggestionsAdapter", "Invalid icon resource " + iconResource + " for " + componentName.flattenToShortString());
            return null;
        } catch (NameNotFoundException e) {
            Log.w("SuggestionsAdapter", e.toString());
            return null;
        }
    }

    private Drawable m2685b(Uri uri) {
        InputStream openInputStream;
        try {
            if ("android.resource".equals(uri.getScheme())) {
                return m2694a(uri);
            }
            openInputStream = this.f1487m.getContentResolver().openInputStream(uri);
            if (openInputStream == null) {
                throw new FileNotFoundException("Failed to open " + uri);
            }
            Drawable createFromStream = Drawable.createFromStream(openInputStream, null);
            try {
                openInputStream.close();
                return createFromStream;
            } catch (Throwable e) {
                Log.e("SuggestionsAdapter", "Error closing icon stream for " + uri, e);
                return createFromStream;
            }
        } catch (NotFoundException e2) {
            throw new FileNotFoundException("Resource does not exist: " + uri);
        } catch (FileNotFoundException e3) {
            Log.w("SuggestionsAdapter", "Icon not found: " + uri + ", " + e3.getMessage());
            return null;
        } catch (Throwable th) {
            try {
                openInputStream.close();
            } catch (Throwable e4) {
                Log.e("SuggestionsAdapter", "Error closing icon stream for " + uri, e4);
            }
        }
    }

    private Drawable m2686b(String str) {
        ConstantState constantState = (ConstantState) this.f1488n.get(str);
        return constantState == null ? null : constantState.newDrawable();
    }

    private CharSequence m2687b(CharSequence charSequence) {
        if (this.f1492r == null) {
            TypedValue typedValue = new TypedValue();
            this.d.getTheme().resolveAttribute(C0233b.textColorSearchUrl, typedValue, true);
            this.f1492r = this.d.getResources().getColorStateList(typedValue.resourceId);
        }
        CharSequence spannableString = new SpannableString(charSequence);
        spannableString.setSpan(new TextAppearanceSpan(null, 0, 0, this.f1492r, null), 0, charSequence.length(), 33);
        return spannableString;
    }

    private void m2688d(Cursor cursor) {
        Bundle extras = cursor != null ? cursor.getExtras() : null;
        if (extras != null && !extras.getBoolean("in_progress")) {
        }
    }

    private Drawable m2689e(Cursor cursor) {
        if (this.f1496v == -1) {
            return null;
        }
        Drawable a = m2678a(cursor.getString(this.f1496v));
        return a == null ? m2691g(cursor) : a;
    }

    private Drawable m2690f(Cursor cursor) {
        return this.f1497w == -1 ? null : m2678a(cursor.getString(this.f1497w));
    }

    private Drawable m2691g(Cursor cursor) {
        Drawable a = m2677a(this.f1486l.getSearchActivity());
        return a != null ? a : this.d.getPackageManager().getDefaultActivityIcon();
    }

    Cursor m2692a(SearchableInfo searchableInfo, String str, int i) {
        if (searchableInfo == null) {
            return null;
        }
        String suggestAuthority = searchableInfo.getSuggestAuthority();
        if (suggestAuthority == null) {
            return null;
        }
        String[] strArr;
        Builder fragment = new Builder().scheme("content").authority(suggestAuthority).query("").fragment("");
        String suggestPath = searchableInfo.getSuggestPath();
        if (suggestPath != null) {
            fragment.appendEncodedPath(suggestPath);
        }
        fragment.appendPath("search_suggest_query");
        String suggestSelection = searchableInfo.getSuggestSelection();
        if (suggestSelection != null) {
            strArr = new String[]{str};
        } else {
            fragment.appendPath(str);
            strArr = null;
        }
        if (i > 0) {
            fragment.appendQueryParameter("limit", String.valueOf(i));
        }
        return this.d.getContentResolver().query(fragment.build(), null, suggestSelection, strArr, null);
    }

    public Cursor m2693a(CharSequence charSequence) {
        String charSequence2 = charSequence == null ? "" : charSequence.toString();
        if (this.f1485k.getVisibility() != 0 || this.f1485k.getWindowVisibility() != 0) {
            return null;
        }
        try {
            Cursor a = m2692a(this.f1486l, charSequence2, 50);
            if (a != null) {
                a.getCount();
                return a;
            }
        } catch (Throwable e) {
            Log.w("SuggestionsAdapter", "Search suggestions query threw an exception.", e);
        }
        return null;
    }

    Drawable m2694a(Uri uri) {
        String authority = uri.getAuthority();
        if (TextUtils.isEmpty(authority)) {
            throw new FileNotFoundException("No authority: " + uri);
        }
        try {
            Resources resourcesForApplication = this.d.getPackageManager().getResourcesForApplication(authority);
            List pathSegments = uri.getPathSegments();
            if (pathSegments == null) {
                throw new FileNotFoundException("No path: " + uri);
            }
            int size = pathSegments.size();
            if (size == 1) {
                try {
                    size = Integer.parseInt((String) pathSegments.get(0));
                } catch (NumberFormatException e) {
                    throw new FileNotFoundException("Single path segment is not a resource ID: " + uri);
                }
            } else if (size == 2) {
                size = resourcesForApplication.getIdentifier((String) pathSegments.get(1), (String) pathSegments.get(0), authority);
            } else {
                throw new FileNotFoundException("More than two path segments: " + uri);
            }
            if (size != 0) {
                return resourcesForApplication.getDrawable(size);
            }
            throw new FileNotFoundException("No resource found for: " + uri);
        } catch (NameNotFoundException e2) {
            throw new FileNotFoundException("No package found for authority: " + uri);
        }
    }

    public View m2695a(Context context, Cursor cursor, ViewGroup viewGroup) {
        View a = super.m1465a(context, cursor, viewGroup);
        a.setTag(new db(a));
        ((ImageView) a.findViewById(C0238g.edit_query)).setImageResource(this.f1489o);
        return a;
    }

    public void m2696a(int i) {
        this.f1491q = i;
    }

    public void m2697a(Cursor cursor) {
        if (this.f1490p) {
            Log.w("SuggestionsAdapter", "Tried to change cursor after adapter was closed.");
            if (cursor != null) {
                cursor.close();
                return;
            }
            return;
        }
        try {
            super.m1459a(cursor);
            if (cursor != null) {
                this.f1493s = cursor.getColumnIndex("suggest_text_1");
                this.f1494t = cursor.getColumnIndex("suggest_text_2");
                this.f1495u = cursor.getColumnIndex("suggest_text_2_url");
                this.f1496v = cursor.getColumnIndex("suggest_icon_1");
                this.f1497w = cursor.getColumnIndex("suggest_icon_2");
                this.f1498x = cursor.getColumnIndex("suggest_flags");
            }
        } catch (Throwable e) {
            Log.e("SuggestionsAdapter", "error changing cursor and caching columns", e);
        }
    }

    public void m2698a(View view, Context context, Cursor cursor) {
        db dbVar = (db) view.getTag();
        int i = this.f1498x != -1 ? cursor.getInt(this.f1498x) : 0;
        if (dbVar.f1499a != null) {
            m2682a(dbVar.f1499a, m2679a(cursor, this.f1493s));
        }
        if (dbVar.f1500b != null) {
            CharSequence a = m2679a(cursor, this.f1495u);
            a = a != null ? m2687b(a) : m2679a(cursor, this.f1494t);
            if (TextUtils.isEmpty(a)) {
                if (dbVar.f1499a != null) {
                    dbVar.f1499a.setSingleLine(false);
                    dbVar.f1499a.setMaxLines(2);
                }
            } else if (dbVar.f1499a != null) {
                dbVar.f1499a.setSingleLine(true);
                dbVar.f1499a.setMaxLines(1);
            }
            m2682a(dbVar.f1500b, a);
        }
        if (dbVar.f1501c != null) {
            m2681a(dbVar.f1501c, m2689e(cursor), 4);
        }
        if (dbVar.f1502d != null) {
            m2681a(dbVar.f1502d, m2690f(cursor), 8);
        }
        if (this.f1491q == 2 || (this.f1491q == 1 && (i & 1) != 0)) {
            dbVar.f1503e.setVisibility(0);
            dbVar.f1503e.setTag(dbVar.f1499a.getText());
            dbVar.f1503e.setOnClickListener(this);
            return;
        }
        dbVar.f1503e.setVisibility(8);
    }

    public CharSequence m2699c(Cursor cursor) {
        if (cursor == null) {
            return null;
        }
        String a = m2680a(cursor, "suggest_intent_query");
        if (a != null) {
            return a;
        }
        if (this.f1486l.shouldRewriteQueryFromData()) {
            a = m2680a(cursor, "suggest_intent_data");
            if (a != null) {
                return a;
            }
        }
        if (!this.f1486l.shouldRewriteQueryFromText()) {
            return null;
        }
        a = m2680a(cursor, "suggest_text_1");
        return a != null ? a : null;
    }

    public View getView(int i, View view, ViewGroup viewGroup) {
        try {
            return super.getView(i, view, viewGroup);
        } catch (Throwable e) {
            Log.w("SuggestionsAdapter", "Search suggestions cursor threw exception.", e);
            View a = m2695a(this.d, this.c, viewGroup);
            if (a != null) {
                ((db) a.getTag()).f1499a.setText(e.toString());
            }
            return a;
        }
    }

    public boolean hasStableIds() {
        return false;
    }

    public void notifyDataSetChanged() {
        super.notifyDataSetChanged();
        m2688d(m1455a());
    }

    public void notifyDataSetInvalidated() {
        super.notifyDataSetInvalidated();
        m2688d(m1455a());
    }

    public void onClick(View view) {
        Object tag = view.getTag();
        if (tag instanceof CharSequence) {
            this.f1485k.m2409a((CharSequence) tag);
        }
    }
}
