import mongoose from "mongoose";
import dotenv from "dotenv"
dotenv.config()

const url = process.env.REACT_APP_DATABASE_URL || "";

const connect = async () => {
    try {
        await mongoose.connect(url);
        const db = mongoose.connection.db;
        const devsquareCollection = db.collection('devsquare');
        console.log("Accessed devsquare collection");
        console.log("Connected to MongoDB");
    } catch (error) {
        console.error("MongoDB connection error:", error);
    }
};

connect();

export const schema = new mongoose.Schema({
  name: "string",
  url: "string",
  id: "string",
  cb_rank: "number",
  region: "string",
  about: "string",
  industries: ["string"],
  operating_status: "string",
  company_type: "string",
  social_media_links: ["string"],
  founded_date: "date",
  num_employees: "string",
  country_code: "string",
  website: "string",
  contact_email: "string",
  contact_phone: "string",
  featured_list: [],
  full_description: "string",
  type: "string",
  uuid: "string",
  active_tech_count: "number",
  builtwith_num_technologies_used: "number",
  builtwith_tech: ["string"],
  ipo_status: "string",
  similar_companies: ["string"],
  image: "string",
  monthly_visits: "number",
  semrush_visits_latest_month: "number",
  semrush_last_updated: "date",
  monthly_visits_growth: "number",
  semrush_visits_mom_pct: "number",
  num_contacts: "number",
  num_contacts_linkedin: "number",
  num_employee_profiles: "number",
  total_active_products: "number",
  num_news: "number",
  funding_rounds: {
    type: "object"
  },
  bombora_last_updated: "date",
  num_investors: "number",
  legal_name: "string",
  num_event_appearances: "number",
  num_acquisitions: "number",
  num_investments: "number",
  num_advisor_positions: "number",
  num_exits: "number",
  num_investments_lead: "number",
  num_sub_organizations: "number",
  num_alumni: "number",
  num_diversity_spotlight_investments: "number",
  num_founder_alumni: "number",
  num_funds: "number",
  stock_symbol: "string",
  location: "string",
  address: "string",
  contacts: "string",
  current_employees: ["string"],
  semrush_location_list: ["string"],
  siftery_products: ["string"],
  funding_rounds_list: ["string"],
  bombora: ["string"],
  investors: ["string"],
  event_appearances: ["string"],
  acquisitions: ["string"],
  funds_raised: ["string"],
  investments: ["string"],
  apptopia: ["string"],
  current_advisors: ["string"],
  exits: ["string"],
  leadership_hire: ["string"],
  sub_organizations: ["string"],
  alumni: ["string"],
  diversity_investments: ["string"],
  funds_list: ["string"],
  layoff: ["string"],
  news: "string",
  aberdeen_it_spend: "string",
  headquarters_regions: "string",
  financials_highlights: "string",
  ipo_fields: {
    type: "object"
  },
  ipqwery: "string",
  overview_highlights: {
    type: "object"
  },
  people_highlights: "string",
  technology_highlights: {
    type: "object"
  },
  founders: "string",
  funds_total: "string",
  acquired_by: "string",
  investor_type: "string",
  investment_stage: "string",
  sub_organization_of: "string",
  apptopia_total_downloads: "string",
  apptopia_total_downloads_mom_pct: "string"
}
);

const investorsSchema = new mongoose.Schema({
  id: Number,
  name: {
    type: String,
    required: true
  },
  slug: {
    type: String,
    required: true,
    unique: true
  },
  title: {
    type: String,
    required: true
  },
  firm: {
    type: String,
    required: true
  },
  bio: {
    type: String,
    required: true
  },
  location: {
    type: String,
    required: true
  },
  investment_focus: [{
    type: String,
    required: true
  }],
  linkedin: {
    type: String,
    required: true
  },
  twitter: {
    type: String,
    required: true
  },
  profile_picture: {
    type: String,
    required: true
  }
});

const foundersSchema = new mongoose.Schema({
  id: Number,
  name: {
    type: String,
    required: true
  },
  slug: {
    type: String,
    required: true,
    unique: true
  },
  title: {
    type: String,
    required: true
  },
  company: {
    type: String,
    required: true
  },
  bio: {
    type: String,
    required: true
  },
  location: {
    type: String,
    required: true
  },
  skills: [{
    type: String,
    required: true
  }],
  linkedin: {
    type: String,
    required: true
  },
  twitter: {
    type: String,
    required: true
  },
  profile_picture: {
    type: String,
    required: true
  }
});

const investors = mongoose.model('investors', investorsSchema , "investors");
const founders = mongoose.model('founders', foundersSchema , "founders");
const data = mongoose.model("data" , schema , "devsquare")

export { data , investors , founders}