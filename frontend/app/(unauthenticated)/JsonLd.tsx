// app/(unauthenticated)/JsonLd.tsx
// Inline <script type="application/ld+json"> for structured data.
// Server-rendered so search engines see it on first paint.

export default function JsonLd({ data }: { data: object | object[] }) {
  return (
    <script
      type="application/ld+json"
      // eslint-disable-next-line react/no-danger
      dangerouslySetInnerHTML={{ __html: JSON.stringify(data) }}
    />
  );
}
