import React from 'react';

const forums = [
  { name: 'Fundraising', description: 'Discuss strategies and ideas for fundraising.', link: '#' },
  { name: 'Marketing', description: 'Share marketing tips and tricks.', link: '#' },
  { name: 'Product Development', description: 'Discuss product development and ideas.', link: '#' },
  { name: 'Customer Support', description: 'Share experiences and strategies for providing excellent customer support.', link: '#' },
  { name: 'Sales', description: 'Discuss sales techniques and share success stories.', link: '#' },
  { name: 'Business Strategy', description: 'Talk about business strategies and growth plans.', link: '#' },
  { name: 'Human Resources', description: 'Discuss HR practices, recruitment, and employee management.', link: '#' },
  { name: 'Finance & Accounting', description: 'Share insights on financial management, accounting, and budgeting.', link: '#' },
  { name: 'Technology & Innovation', description: 'Discuss the latest technology trends and innovative solutions.', link: '#' },
  { name: 'Legal & Compliance', description: 'Talk about legal issues and compliance requirements.', link: '#' },
  { name: 'Networking', description: 'Share networking tips and connect with other professionals.', link: '#' },
  { name: 'Entrepreneurship', description: 'Discuss challenges and successes in starting and running a business.', link: '#' },
  { name: 'Project Management', description: 'Share project management tips, tools, and best practices.', link: '#' },
  { name: 'Operations & Logistics', description: 'Discuss operational efficiencies and logistics strategies.', link: '#' },
  { name: 'Leadership', description: 'Talk about leadership skills and strategies for leading teams.', link: '#' }
];

function Form({ name, description, link }) {
  return (
    <a href={link} className="w-full sm:w-1/2 md:w-1/3 lg:w-1/3 xl:w-1/3 p-4 ">
      <div className="bg-white shadow-lg rounded-lg overflow-hidden transform hover:scale-105 transition-transform duration-200 border">
        <div className="px-6 py-4">
          <div className="font-bold text-xl mb-2 text-blue-600">{name}</div>
          <p className="text-gray-700 text-base">
            {description}
          </p>
        </div>
      </div>
    </a>
  );
}

export default function Forum() {
  return (
    <div className="min-h-screen bg-100 flex flex-col items-center ">
      {/* <header className="w-full bg-blue-500 text-white py-6 text-center">
        <h1 className="text-3xl font-bold">Forum Topics</h1>
      </header> */}
      <main className="flex-grow w-full px-4 py-8 flex justify-center">
        <div className="flex flex-wrap justify-center">
          {forums.map((forum, index) => (
            <Form key={index} name={forum.name} description={forum.description} link={forum.link} />
          ))}
        </div>
      </main>
    </div>
  );
}


