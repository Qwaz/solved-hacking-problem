package android.support.v7.widget;

import android.annotation.TargetApi;
import android.app.SearchableInfo;
import android.content.Context;
import android.content.Intent;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.os.Parcelable;
import android.support.v4.widget.C0176m;
import android.support.v7.p015b.C0233b;
import android.support.v7.p015b.C0236e;
import android.support.v7.p015b.C0243l;
import android.support.v7.view.C0248d;
import android.text.SpannableStringBuilder;
import android.text.TextUtils;
import android.text.style.ImageSpan;
import android.util.AttributeSet;
import android.view.KeyEvent;
import android.view.KeyEvent.DispatcherState;
import android.view.View;
import android.view.View.MeasureSpec;
import android.view.View.OnClickListener;
import android.view.View.OnFocusChangeListener;
import android.view.inputmethod.InputMethodManager;
import android.widget.ImageView;
import java.util.WeakHashMap;

public class SearchView extends bw implements C0248d {
    static final cu f1187a;
    private static final boolean f1188b;
    private boolean f1189A;
    private boolean f1190B;
    private int f1191C;
    private boolean f1192D;
    private CharSequence f1193E;
    private boolean f1194F;
    private int f1195G;
    private SearchableInfo f1196H;
    private Bundle f1197I;
    private Runnable f1198J;
    private final Runnable f1199K;
    private Runnable f1200L;
    private final WeakHashMap f1201M;
    private final SearchAutoComplete f1202c;
    private final View f1203d;
    private final View f1204e;
    private final ImageView f1205f;
    private final ImageView f1206g;
    private final ImageView f1207h;
    private final ImageView f1208i;
    private final ImageView f1209j;
    private final Drawable f1210k;
    private final int f1211l;
    private final int f1212m;
    private final Intent f1213n;
    private final Intent f1214o;
    private final CharSequence f1215p;
    private cw f1216q;
    private cv f1217r;
    private OnFocusChangeListener f1218s;
    private cx f1219t;
    private OnClickListener f1220u;
    private boolean f1221v;
    private boolean f1222w;
    private C0176m f1223x;
    private boolean f1224y;
    private CharSequence f1225z;

    public class SearchAutoComplete extends ai {
        private int f1185a;
        private SearchView f1186b;

        public SearchAutoComplete(Context context) {
            this(context, null);
        }

        public SearchAutoComplete(Context context, AttributeSet attributeSet) {
            this(context, attributeSet, C0233b.autoCompleteTextViewStyle);
        }

        public SearchAutoComplete(Context context, AttributeSet attributeSet, int i) {
            super(context, attributeSet, i);
            this.f1185a = getThreshold();
        }

        public boolean enoughToFilter() {
            return this.f1185a <= 0 || super.enoughToFilter();
        }

        protected void onFocusChanged(boolean z, int i, Rect rect) {
            super.onFocusChanged(z, i, rect);
            this.f1186b.m2413d();
        }

        public boolean onKeyPreIme(int i, KeyEvent keyEvent) {
            if (i == 4) {
                DispatcherState keyDispatcherState;
                if (keyEvent.getAction() == 0 && keyEvent.getRepeatCount() == 0) {
                    keyDispatcherState = getKeyDispatcherState();
                    if (keyDispatcherState == null) {
                        return true;
                    }
                    keyDispatcherState.startTracking(keyEvent, this);
                    return true;
                } else if (keyEvent.getAction() == 1) {
                    keyDispatcherState = getKeyDispatcherState();
                    if (keyDispatcherState != null) {
                        keyDispatcherState.handleUpEvent(keyEvent);
                    }
                    if (keyEvent.isTracking() && !keyEvent.isCanceled()) {
                        this.f1186b.clearFocus();
                        this.f1186b.setImeVisibility(false);
                        return true;
                    }
                }
            }
            return super.onKeyPreIme(i, keyEvent);
        }

        public void onWindowFocusChanged(boolean z) {
            super.onWindowFocusChanged(z);
            if (z && this.f1186b.hasFocus() && getVisibility() == 0) {
                ((InputMethodManager) getContext().getSystemService("input_method")).showSoftInput(this, 0);
                if (SearchView.m2392a(getContext())) {
                    SearchView.f1187a.m2671a(this, true);
                }
            }
        }

        public void performCompletion() {
        }

        protected void replaceText(CharSequence charSequence) {
        }

        void setSearchView(SearchView searchView) {
            this.f1186b = searchView;
        }

        public void setThreshold(int i) {
            super.setThreshold(i);
            this.f1185a = i;
        }
    }

    static {
        f1188b = VERSION.SDK_INT >= 8;
        f1187a = new cu();
    }

    private Intent m2388a(String str, Uri uri, String str2, String str3, int i, String str4) {
        Intent intent = new Intent(str);
        intent.addFlags(268435456);
        if (uri != null) {
            intent.setData(uri);
        }
        intent.putExtra("user_query", this.f1193E);
        if (str3 != null) {
            intent.putExtra("query", str3);
        }
        if (str2 != null) {
            intent.putExtra("intent_extra_data_key", str2);
        }
        if (this.f1197I != null) {
            intent.putExtra("app_data", this.f1197I);
        }
        if (i != 0) {
            intent.putExtra("action_key", i);
            intent.putExtra("action_msg", str4);
        }
        if (f1188b) {
            intent.setComponent(this.f1196H.getSearchActivity());
        }
        return intent;
    }

    private void m2389a(int i, String str, String str2) {
        getContext().startActivity(m2388a("android.intent.action.SEARCH", null, null, str2, i, str));
    }

    private void m2391a(boolean z) {
        boolean z2 = true;
        int i = 8;
        this.f1222w = z;
        int i2 = z ? 0 : 8;
        boolean z3 = !TextUtils.isEmpty(this.f1202c.getText());
        this.f1205f.setVisibility(i2);
        m2394b(z3);
        this.f1203d.setVisibility(z ? 8 : 0);
        if (!(this.f1209j.getDrawable() == null || this.f1221v)) {
            i = 0;
        }
        this.f1209j.setVisibility(i);
        m2399h();
        if (z3) {
            z2 = false;
        }
        m2395c(z2);
        m2398g();
    }

    static boolean m2392a(Context context) {
        return context.getResources().getConfiguration().orientation == 2;
    }

    private CharSequence m2393b(CharSequence charSequence) {
        if (!this.f1221v || this.f1210k == null) {
            return charSequence;
        }
        int textSize = (int) (((double) this.f1202c.getTextSize()) * 1.25d);
        this.f1210k.setBounds(0, 0, textSize, textSize);
        SpannableStringBuilder spannableStringBuilder = new SpannableStringBuilder("   ");
        spannableStringBuilder.setSpan(new ImageSpan(this.f1210k), 1, 2, 33);
        spannableStringBuilder.append(charSequence);
        return spannableStringBuilder;
    }

    private void m2394b(boolean z) {
        int i = 8;
        if (this.f1224y && m2397f() && hasFocus() && (z || !this.f1192D)) {
            i = 0;
        }
        this.f1206g.setVisibility(i);
    }

    private void m2395c(boolean z) {
        int i;
        if (this.f1192D && !m2412c() && z) {
            i = 0;
            this.f1206g.setVisibility(8);
        } else {
            i = 8;
        }
        this.f1208i.setVisibility(i);
    }

    @TargetApi(8)
    private boolean m2396e() {
        if (this.f1196H == null || !this.f1196H.getVoiceSearchEnabled()) {
            return false;
        }
        Intent intent = null;
        if (this.f1196H.getVoiceSearchLaunchWebSearch()) {
            intent = this.f1213n;
        } else if (this.f1196H.getVoiceSearchLaunchRecognizer()) {
            intent = this.f1214o;
        }
        return (intent == null || getContext().getPackageManager().resolveActivity(intent, 65536) == null) ? false : true;
    }

    private boolean m2397f() {
        return (this.f1224y || this.f1192D) && !m2412c();
    }

    private void m2398g() {
        int i = 8;
        if (m2397f() && (this.f1206g.getVisibility() == 0 || this.f1208i.getVisibility() == 0)) {
            i = 0;
        }
        this.f1204e.setVisibility(i);
    }

    private int getPreferredWidth() {
        return getContext().getResources().getDimensionPixelSize(C0236e.abc_search_view_preferred_width);
    }

    private void m2399h() {
        int i = 1;
        int i2 = 0;
        int i3 = !TextUtils.isEmpty(this.f1202c.getText()) ? 1 : 0;
        if (i3 == 0 && (!this.f1221v || this.f1194F)) {
            i = 0;
        }
        ImageView imageView = this.f1207h;
        if (i == 0) {
            i2 = 8;
        }
        imageView.setVisibility(i2);
        Drawable drawable = this.f1207h.getDrawable();
        if (drawable != null) {
            drawable.setState(i3 != 0 ? ENABLED_STATE_SET : EMPTY_STATE_SET);
        }
    }

    private void m2400i() {
        post(this.f1199K);
    }

    private void m2401k() {
        CharSequence queryHint = getQueryHint();
        SearchAutoComplete searchAutoComplete = this.f1202c;
        if (queryHint == null) {
            queryHint = "";
        }
        searchAutoComplete.setHint(m2393b(queryHint));
    }

    @TargetApi(8)
    private void m2402l() {
        int i = 1;
        this.f1202c.setThreshold(this.f1196H.getSuggestThreshold());
        this.f1202c.setImeOptions(this.f1196H.getImeOptions());
        int inputType = this.f1196H.getInputType();
        if ((inputType & 15) == 1) {
            inputType &= -65537;
            if (this.f1196H.getSuggestAuthority() != null) {
                inputType = (inputType | 65536) | 524288;
            }
        }
        this.f1202c.setInputType(inputType);
        if (this.f1223x != null) {
            this.f1223x.m1459a(null);
        }
        if (this.f1196H.getSuggestAuthority() != null) {
            this.f1223x = new da(getContext(), this, this.f1196H, this.f1201M);
            this.f1202c.setAdapter(this.f1223x);
            da daVar = (da) this.f1223x;
            if (this.f1189A) {
                i = 2;
            }
            daVar.m2696a(i);
        }
    }

    private void m2403m() {
        CharSequence text = this.f1202c.getText();
        if (text != null && TextUtils.getTrimmedLength(text) > 0) {
            if (this.f1216q == null || !this.f1216q.m2674a(text.toString())) {
                if (this.f1196H != null) {
                    m2389a(0, null, text.toString());
                }
                setImeVisibility(false);
                m2404n();
            }
        }
    }

    private void m2404n() {
        this.f1202c.dismissDropDown();
    }

    private void m2405o() {
        if (!TextUtils.isEmpty(this.f1202c.getText())) {
            this.f1202c.setText("");
            this.f1202c.requestFocus();
            setImeVisibility(true);
        } else if (!this.f1221v) {
        } else {
            if (this.f1217r == null || !this.f1217r.m2673a()) {
                clearFocus();
                m2391a(true);
            }
        }
    }

    private void m2406p() {
        m2391a(false);
        this.f1202c.requestFocus();
        setImeVisibility(true);
        if (this.f1220u != null) {
            this.f1220u.onClick(this);
        }
    }

    private void m2407q() {
        f1187a.m2670a(this.f1202c);
        f1187a.m2672b(this.f1202c);
    }

    private void setImeVisibility(boolean z) {
        if (z) {
            post(this.f1198J);
            return;
        }
        removeCallbacks(this.f1198J);
        InputMethodManager inputMethodManager = (InputMethodManager) getContext().getSystemService("input_method");
        if (inputMethodManager != null) {
            inputMethodManager.hideSoftInputFromWindow(getWindowToken(), 0);
        }
    }

    private void setQuery(CharSequence charSequence) {
        this.f1202c.setText(charSequence);
        this.f1202c.setSelection(TextUtils.isEmpty(charSequence) ? 0 : charSequence.length());
    }

    public void m2408a() {
        if (!this.f1194F) {
            this.f1194F = true;
            this.f1195G = this.f1202c.getImeOptions();
            this.f1202c.setImeOptions(this.f1195G | 33554432);
            this.f1202c.setText("");
            setIconified(false);
        }
    }

    void m2409a(CharSequence charSequence) {
        setQuery(charSequence);
    }

    public void m2410a(CharSequence charSequence, boolean z) {
        this.f1202c.setText(charSequence);
        if (charSequence != null) {
            this.f1202c.setSelection(this.f1202c.length());
            this.f1193E = charSequence;
        }
        if (z && !TextUtils.isEmpty(charSequence)) {
            m2403m();
        }
    }

    public void m2411b() {
        m2410a((CharSequence) "", false);
        clearFocus();
        m2391a(true);
        this.f1202c.setImeOptions(this.f1195G);
        this.f1194F = false;
    }

    public boolean m2412c() {
        return this.f1222w;
    }

    public void clearFocus() {
        this.f1190B = true;
        setImeVisibility(false);
        super.clearFocus();
        this.f1202c.clearFocus();
        this.f1190B = false;
    }

    void m2413d() {
        m2391a(m2412c());
        m2400i();
        if (this.f1202c.hasFocus()) {
            m2407q();
        }
    }

    public int getImeOptions() {
        return this.f1202c.getImeOptions();
    }

    public int getInputType() {
        return this.f1202c.getInputType();
    }

    public int getMaxWidth() {
        return this.f1191C;
    }

    public CharSequence getQuery() {
        return this.f1202c.getText();
    }

    public CharSequence getQueryHint() {
        return this.f1225z != null ? this.f1225z : (!f1188b || this.f1196H == null || this.f1196H.getHintId() == 0) ? this.f1215p : getContext().getText(this.f1196H.getHintId());
    }

    int getSuggestionCommitIconResId() {
        return this.f1212m;
    }

    int getSuggestionRowLayout() {
        return this.f1211l;
    }

    public C0176m getSuggestionsAdapter() {
        return this.f1223x;
    }

    protected void onDetachedFromWindow() {
        removeCallbacks(this.f1199K);
        post(this.f1200L);
        super.onDetachedFromWindow();
    }

    protected void onMeasure(int i, int i2) {
        if (m2412c()) {
            super.onMeasure(i, i2);
            return;
        }
        int mode = MeasureSpec.getMode(i);
        int size = MeasureSpec.getSize(i);
        switch (mode) {
            case Integer.MIN_VALUE:
                if (this.f1191C <= 0) {
                    size = Math.min(getPreferredWidth(), size);
                    break;
                } else {
                    size = Math.min(this.f1191C, size);
                    break;
                }
            case C0243l.View_android_theme /*0*/:
                if (this.f1191C <= 0) {
                    size = getPreferredWidth();
                    break;
                } else {
                    size = this.f1191C;
                    break;
                }
            case 1073741824:
                if (this.f1191C > 0) {
                    size = Math.min(this.f1191C, size);
                    break;
                }
                break;
        }
        super.onMeasure(MeasureSpec.makeMeasureSpec(size, 1073741824), i2);
    }

    protected void onRestoreInstanceState(Parcelable parcelable) {
        if (parcelable instanceof cy) {
            cy cyVar = (cy) parcelable;
            super.onRestoreInstanceState(cyVar.getSuperState());
            m2391a(cyVar.f1483a);
            requestLayout();
            return;
        }
        super.onRestoreInstanceState(parcelable);
    }

    protected Parcelable onSaveInstanceState() {
        Parcelable cyVar = new cy(super.onSaveInstanceState());
        cyVar.f1483a = m2412c();
        return cyVar;
    }

    public void onWindowFocusChanged(boolean z) {
        super.onWindowFocusChanged(z);
        m2400i();
    }

    public boolean requestFocus(int i, Rect rect) {
        if (this.f1190B || !isFocusable()) {
            return false;
        }
        if (m2412c()) {
            return super.requestFocus(i, rect);
        }
        boolean requestFocus = this.f1202c.requestFocus(i, rect);
        if (requestFocus) {
            m2391a(false);
        }
        return requestFocus;
    }

    public void setAppSearchData(Bundle bundle) {
        this.f1197I = bundle;
    }

    public void setIconified(boolean z) {
        if (z) {
            m2405o();
        } else {
            m2406p();
        }
    }

    public void setIconifiedByDefault(boolean z) {
        if (this.f1221v != z) {
            this.f1221v = z;
            m2391a(z);
            m2401k();
        }
    }

    public void setImeOptions(int i) {
        this.f1202c.setImeOptions(i);
    }

    public void setInputType(int i) {
        this.f1202c.setInputType(i);
    }

    public void setMaxWidth(int i) {
        this.f1191C = i;
        requestLayout();
    }

    public void setOnCloseListener(cv cvVar) {
        this.f1217r = cvVar;
    }

    public void setOnQueryTextFocusChangeListener(OnFocusChangeListener onFocusChangeListener) {
        this.f1218s = onFocusChangeListener;
    }

    public void setOnQueryTextListener(cw cwVar) {
        this.f1216q = cwVar;
    }

    public void setOnSearchClickListener(OnClickListener onClickListener) {
        this.f1220u = onClickListener;
    }

    public void setOnSuggestionListener(cx cxVar) {
        this.f1219t = cxVar;
    }

    public void setQueryHint(CharSequence charSequence) {
        this.f1225z = charSequence;
        m2401k();
    }

    public void setQueryRefinementEnabled(boolean z) {
        this.f1189A = z;
        if (this.f1223x instanceof da) {
            ((da) this.f1223x).m2696a(z ? 2 : 1);
        }
    }

    public void setSearchableInfo(SearchableInfo searchableInfo) {
        this.f1196H = searchableInfo;
        if (this.f1196H != null) {
            if (f1188b) {
                m2402l();
            }
            m2401k();
        }
        boolean z = f1188b && m2396e();
        this.f1192D = z;
        if (this.f1192D) {
            this.f1202c.setPrivateImeOptions("nm");
        }
        m2391a(m2412c());
    }

    public void setSubmitButtonEnabled(boolean z) {
        this.f1224y = z;
        m2391a(m2412c());
    }

    public void setSuggestionsAdapter(C0176m c0176m) {
        this.f1223x = c0176m;
        this.f1202c.setAdapter(this.f1223x);
    }
}
