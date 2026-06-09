# Monetization setup -- step by step

What you need to do, in your accounts, to take real money. None of this is automatable from outside your accounts.

Approximate time: **45 minutes total**, broken into 10-minute chunks.

---

## Step 1 -- Enable GitHub Sponsors (10 minutes)

You need: a GitHub account (have it), a Stripe-eligible country (most US/EU/UK/AU/etc count), and a bank account or PayPal for payouts.

1. Visit <https://github.com/sponsors/accounts/new>
2. Click **Get started** (it's a yellow button on the right)
3. GitHub will ask which account to set up: pick **Bikebrainz**
4. Fill in:
   - **Display name**: Bikebrainz
   - **Short bio**: "Maintainer of Nullock -- FOSS web security toolkit"
   - **Goal**: pick one, e.g. "$500/mo to cover code-signing + domain costs"
5. Connect Stripe Connect (5 minutes of bank form)
6. Add the four tiers from `SPONSOR.md`:
   - $5 -- Coffee fund
   - $25 -- Curious supporter
   - $99 -- Pro user
   - $499 -- Business / consulting use
7. Submit for review. GitHub usually approves within 1-3 business days.

**After approval**, the `.github/FUNDING.yml` file in this repo automatically activates the **Sponsor button** at the top of the repo page. You don't have to do anything else.

The sponsor link will be: <https://github.com/sponsors/Bikebrainz>

---

## Step 2 -- Create Stripe Payment Links (10 minutes)

Stripe is the easiest path because it's free until you take money (then ~2.9% + 30¢ per transaction).

1. Visit <https://dashboard.stripe.com/register> -- 5 minutes to create an account
2. Skip the integration questions; you don't need an API key for Payment Links
3. Once logged in, go to **Products** -> **Add product**
4. Create three products:

### Product 1: Nullock Premium Support
- Name: **Nullock Premium Support**
- Description: *48h email SLA, direct line to maintainer, priority bug-fix queue, 1 custom extension review per month. Cancel any time.*
- Pricing: **Recurring**, **$99 / year**
- Currency: USD

### Product 2: Nullock Business Support
- Name: **Nullock Business Support**
- Description: *24h email SLA, all Premium benefits, sponsor logo placement, quarterly 1h video call, up to 10 named seats. Cancel any time.*
- Pricing: **Recurring**, **$499 / year**
- Currency: USD

### Product 3 (optional, set up later): One-time consulting
- Name: **Nullock Engagement Support -- one-time**
- Description: *4-hour block of maintainer time. Email + same-day Slack response, no SLA commitment beyond the block.*
- Pricing: **One-time**, **$499** (or whatever you want for an hour, scaled)
- Currency: USD

5. For each product, click **Create payment link**
6. Copy the resulting URL (looks like `https://buy.stripe.com/xxxxx`)

You now have three URLs. **Save them somewhere** -- you'll paste them into the HTML in step 4.

---

## Step 3 -- Test mode first (5 minutes, optional but recommended)

Stripe ships test cards (`4242 4242 4242 4242` etc). Before flipping a payment link to **live**, run it through test mode and confirm:

- Receipt email arrives
- Subscription shows up in **Customers**
- Cancellation works from the Stripe portal

When the test succeeds, in the dashboard click the **toggle in the top right** to switch from "Test mode" -> "Live mode" and re-create the products in live mode. (Stripe deliberately keeps the two modes separate.)

---

## Step 4 -- Wire the URLs into the site (5 minutes)

Open `docs/support.html` and `docs/pricing.html`. Search for `STRIPE_PAYMENT_LINK_HERE` and `STRIPE_PAYMENT_LINK_BUSINESS_HERE`. Replace with the URLs from Step 2.

Or just `sed`:
```sh
sed -i 's|STRIPE_PAYMENT_LINK_HERE|https://buy.stripe.com/YOUR_PREMIUM_URL|g' docs/support.html docs/pricing.html
sed -i 's|STRIPE_PAYMENT_LINK_BUSINESS_HERE|https://buy.stripe.com/YOUR_BUSINESS_URL|g' docs/support.html docs/pricing.html
```

Commit and push. The pages workflow auto-deploys the docs site.

---

## Step 5 -- Enable GitHub Pages (5 minutes)

Once `.github/workflows/pages.yml` has run at least once:

1. Go to **Settings** -> **Pages** in your repo
2. Source: **GitHub Actions**
3. The site goes live at `https://bikebrainz.github.io/Nullock/`

The Pages workflow already exists; it'll deploy on the next push to `docs/`. After today's commit, you should be able to visit:

- `https://bikebrainz.github.io/Nullock/` -- landing page
- `https://bikebrainz.github.io/Nullock/pricing.html` -- pricing
- `https://bikebrainz.github.io/Nullock/support.html` -- premium support
- `https://bikebrainz.github.io/Nullock/components.html` -- brand kit live preview
- `https://bikebrainz.github.io/Nullock/marketplace/` -- extensions

---

## Step 6 -- Announce (10 minutes)

You now have a real product with a real purchase flow. Time to tell someone.

### Minimal launch list

1. **Hacker News** -- Show HN post. Title: `Show HN: Nullock -- FOSS Burp alternative with native gRPC/GraphQL/OAST`
   - Body: 3-4 paragraphs. What it is, what makes it different, link to comparison page, ask for feedback. Don't oversell.
2. **r/netsec** -- 2-3 sentences + the link
3. **Twitter / X / Mastodon** -- a thread of 5-6 short posts with screenshots of: the proxy view, an OAST callback hit, the AI triage panel
4. **LinkedIn** -- if you want enterprise leads, post there with a longer "why I built this" angle
5. **Update your GitHub profile bio** -- "Maintainer of Nullock <https://nullock.io>"

### Don't do yet

- Paid ads (you have nothing to A/B test against)
- Cold email outreach (you have no track record)
- Reaching out to journalists (not enough story yet)

---

## What earning looks like in month 1

Realistic expectations, NOT promises:

| Source | Expected month-1 revenue |
|---|---|
| GitHub Sponsors | $0-200 (early stage, few starbacks yet) |
| Premium subscriptions | $0-300 (3 customers if you're lucky) |
| Business subscriptions | $0-499 (one customer = made the month) |
| One-time consulting | $0-2000 (one Discord DM can turn into this) |
| **Total** | **$0-3000** |

Month 2-3 should roughly double per month if your launch generated stars. Month 6 is the make-or-break read: are people coming back, or did launch hype fade?

If month 6 is below $1500/mo MRR, you have a great hobby project. If it's above $1500, you have the foundation of a one-person business. If it's above $5k, you start thinking about a hire.

---

## What if I want to skip GitHub Sponsors entirely?

You can. Stripe Payment Links + the support landing page work standalone. GitHub Sponsors adds:
- A "Sponsor" button on the repo page (more visibility)
- Sponsor badge on backers' GitHub profiles (slight viral effect)
- No middleman -- direct payout vs Stripe's 2.9% (well, GitHub Sponsors actually has its own fee in some countries, check the docs)

Recommendation: do both. Both are free to set up and they appeal to different buyers (Sponsors = supporting OSS; Stripe = buying a product).

---

## Future revenue surfaces (not now, but in 3-6 months)

| Surface | Setup needed |
|---|---|
| **Cloud OAST** ($9-49/mo subscription) | Domain + VPS + simple Stripe metering |
| **Cross-machine sync** ($19/seat/mo) | Backend storage + auth |
| **Workshop / training** ($1-5k/day) | Just post a calendar link |
| **One-time commercial license** ($1-5k) | One PDF + Stripe Payment Link |
| **Custom extension dev** (project-based) | Just an email inquiry path |
| **Web Security Academy clone + cert** ($99-299/exam) | 6-12 months content work |

All of these compound. Get the basics (Sponsors + Premium / Business) in place first.

---

## What this document doesn't cover

- **Sales tax / VAT.** Stripe Tax handles this for ~0.5% extra per transaction. Enable it once you cross a state's nexus threshold (usually $100k or 200 transactions). Until then, you legally owe sales tax in your home state only -- consult an accountant.
- **Incorporating.** You can take money as a sole proprietor up to a point. Above ~$20k/yr, an LLC starts making sense for liability + tax reasons. ~$200 in your state to file.
- **International payments.** Stripe handles 135+ currencies. Plays well with EU GDPR, UK, Australia. Less smooth with India / Brazil / China -- consider PayPal as a backup link.

For all of the above, the answer is "consult an accountant once you're over $1k/mo." Don't preemptively optimize.

---

## Update this file with real numbers

When you do step 1-5, come back here and replace these placeholders with the real values:

- `STRIPE_PAYMENT_LINK_HERE` -> _your $99/year link_
- `STRIPE_PAYMENT_LINK_BUSINESS_HERE` -> _your $499/year link_
- GitHub Sponsors URL: `https://github.com/sponsors/Bikebrainz`

That's it. Once those three URLs work, you've got a buyable product.
